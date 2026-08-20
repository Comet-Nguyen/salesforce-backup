"""cfn-lint custom rule: SoD encrypt-only guard for the backup stack.

Fails the lint when ANY IAM policy in the template grants an action that
would let the workload read backup data back:

  - s3:GetObject / s3:GetObjectVersion / s3:ListBucket
  - kms:Decrypt

Being structure-aware (real Action lists, not text matching), it also
catches what a text grep cannot: wildcard grants such as `s3:*`, `s3:Get*`
or `kms:*`, which would silently include the forbidden actions.

SCOPE (Architect review finding #3, 2026-08-10): this template declares
permissions almost entirely via SAM's `AWS::Serverless::Function` /
`AWS::Serverless::StateMachine` inline `Policies:` shorthand - it does not
declare raw `AWS::IAM::Role`/`Policy`/`ManagedPolicy` resources. cfn-lint's
custom-rule Template object exposes the PRE-TRANSFORM resource dict, so a
rule scoped only to the raw IAM types finds nothing here - not because the
template is clean, but because the rule never looks in the right place.
Confirmed by direct reproduction: injecting s3:GetObject into a Function's
`Policies: - Statement: [...]` block produced zero findings under the old
scope. This version scans BOTH shapes:
  - Raw IAM resources (Policies[].PolicyDocument, top-level PolicyDocument)
    - kept for defense-in-depth, in case a future change adds one
  - SAM Policies[] entries shaped `{Statement: [...]}` or
    `{PolicyDocument: {...}}` - the actual shape used throughout this
    template today
Each Policies[] entry may also be a plain string (a managed-policy
ARN/name reference) or a SAM Policy Template (a single-key dict naming a
canned AWS template, e.g. `LambdaInvokePolicy`) - both are skipped, since
neither is a literal Statement list this rule can evaluate. SAM Policy
Templates are a known, documented gap: if a future change introduces one
of AWS's read-capable canned templates (e.g. S3ReadPolicy), this rule will
NOT catch it. Reviewers should still eyeball Policies[] entries that are
plain strings during PR review.

Rule ID E9001 (E = error severity, 9xxx = custom-rule namespace).
Usage: cfn-lint template.yaml --append-rules .github/cfn-lint-rules
"""

from fnmatch import fnmatch
from typing import ClassVar

from cfnlint.rules import CloudFormationLintRule, RuleMatch

# Concrete actions the backup role must never be able to perform.
# Includes the wider read/enumeration family (object attributes, version
# listing) so partial wildcards like s3:List* or s3:GetObject* are caught
# through fnmatch coverage in either direction.
FORBIDDEN_ACTIONS = (
    "s3:getobject",
    "s3:getobjectversion",
    "s3:getobjectattributes",
    "s3:listbucket",
    "s3:listbucketversions",
    "kms:decrypt",
)

# Resource types that may carry a raw IAM policy document directly.
IAM_RESOURCE_TYPES = (
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
)

# SAM resource types whose `Properties.Policies` list is where this
# template actually declares its Lambda/state-machine execution
# permissions (SAM auto-generates the underlying IAM::Role at transform
# time - a stage this rule, and cfn-lint's Template object, never sees).
SAM_RESOURCE_TYPES = (
    "AWS::Serverless::Function",
    "AWS::Serverless::StateMachine",
)


class SodBackupRoleEncryptOnly(CloudFormationLintRule):
    id = "E9001"
    shortdesc = "SoD violation: backup role must remain encrypt-only"
    description = (
        "The CISO segregation-of-duties design requires the backup workload "
        "to be write-only: it must never hold s3:GetObject, s3:ListBucket or "
        "kms:Decrypt, including via wildcard grants (s3:*, kms:*, s3:Get*). "
        "Scans both raw AWS::IAM::* resources and SAM Function/StateMachine "
        "Policies[] blocks (fail-closed): scoping by resource name would "
        "let a renamed or new role slip through. "
        "NOTE: do NOT set self.severity in __init__ - it is a read-only "
        "property in modern cfn-lint and raises AttributeError, which "
        "silently prevents the rule from loading at all."
    )
    source_url = "https://internal-wiki/SoD-backup-role"
    tags: ClassVar[list[str]] = ["iam", "security", "sod", "least-privilege"]

    def _statement_violations(self, statement, path):
        matches = []
        if not isinstance(statement, dict):
            return matches
        if statement.get("Effect") != "Allow":
            return matches
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            return matches
        for idx, action in enumerate(actions):
            if not isinstance(action, str):
                continue
            pattern = action.lower()
            for forbidden in FORBIDDEN_ACTIONS:
                # fnmatch answers: does this grant PATTERN cover the
                # forbidden concrete action? ("s3:get*" covers s3:getobject)
                if fnmatch(forbidden, pattern):
                    matches.append(
                        RuleMatch(
                            path + ["Action", idx],
                            f"SoD violation: action grant '{action}' covers "
                            f"forbidden action '{forbidden}' - the backup "
                            f"role must remain encrypt-only "
                            f"(no read-back of backup data).",
                        )
                    )
                    break  # one finding per action entry is enough
        return matches

    def _policy_document_violations(self, doc, path):
        matches = []
        if not isinstance(doc, dict):
            return matches
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for idx, statement in enumerate(statements):
            matches.extend(
                self._statement_violations(statement, path + ["Statement", idx])
            )
        return matches

    def _raw_iam_violations(self, logical_id, resource):
        """Handles AWS::IAM::Role / Policy / ManagedPolicy resources, if any
        ever appear in this template (none do today - see module docstring).
        """
        matches = []
        properties = resource.get("Properties", {})
        if not isinstance(properties, dict):
            return matches
        base = ["Resources", logical_id, "Properties"]

        for p_idx, policy in enumerate(properties.get("Policies", []) or []):
            if isinstance(policy, dict):
                matches.extend(
                    self._policy_document_violations(
                        policy.get("PolicyDocument", {}),
                        base + ["Policies", p_idx, "PolicyDocument"],
                    )
                )

        matches.extend(
            self._policy_document_violations(
                properties.get("PolicyDocument", {}),
                base + ["PolicyDocument"],
            )
        )
        return matches

    def _sam_policies_violations(self, logical_id, resource):
        """Handles AWS::Serverless::Function / StateMachine's Properties.
        Policies list - the shape actually used throughout this template.
        Each entry is one of:
          - str: a managed-policy ARN or name reference -> skipped, not a
            literal Statement list
          - dict with "Statement": SAM's inline-statement shorthand
            (`Policies: - Statement: [...]`) -> evaluated directly
          - dict with "PolicyDocument": a fuller IAM::Policy-shaped block
            -> evaluated via PolicyDocument.Statement
          - dict, single key, neither of the above: a SAM Policy Template
            (e.g. `LambdaInvokePolicy: {FunctionName: ...}`) -> skipped,
            see module docstring's documented-gap note
        """
        matches = []
        properties = resource.get("Properties", {})
        if not isinstance(properties, dict):
            return matches
        base = ["Resources", logical_id, "Properties", "Policies"]

        for p_idx, policy in enumerate(properties.get("Policies", []) or []):
            if not isinstance(policy, dict):
                continue  # managed-policy string reference - not evaluable
            if "Statement" in policy:
                matches.extend(self._policy_document_violations(policy, [*base, p_idx]))
            elif "PolicyDocument" in policy:
                matches.extend(
                    self._policy_document_violations(
                        policy["PolicyDocument"],
                        [*base, p_idx, "PolicyDocument"],
                    )
                )
            # else: SAM Policy Template dict - documented gap, not evaluated
        return matches

    def match(self, cfn):
        matches = []
        resources = cfn.template.get("Resources", {})
        for logical_id, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get("Type")
            if resource_type in IAM_RESOURCE_TYPES:
                matches.extend(self._raw_iam_violations(logical_id, resource))
            elif resource_type in SAM_RESOURCE_TYPES:
                matches.extend(self._sam_policies_violations(logical_id, resource))
        return matches
