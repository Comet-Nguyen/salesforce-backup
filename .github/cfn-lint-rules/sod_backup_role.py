"""cfn-lint custom rule: SoD encrypt-only guard for the backup stack.

Fails the lint when ANY IAM policy in the template grants an action that
would let the workload read backup data back:

  - s3:GetObject / s3:GetObjectVersion / s3:ListBucket
  - kms:Decrypt

Being structure-aware (post-SAM-transform IAM roles, real Action lists), it
also catches what a text grep cannot: wildcard grants such as `s3:*`,
`s3:Get*` or `kms:*`, which would silently include the forbidden actions.

Rule ID E9001 (E = error severity, 9xxx = custom-rule namespace).
Usage: cfn-lint template.yaml --append-rules .github/cfn-lint-rules
"""

from fnmatch import fnmatch

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

IAM_RESOURCE_TYPES = (
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
)


class SodBackupRoleEncryptOnly(CloudFormationLintRule):
    id = "E9001"
    shortdesc = "SoD violation: backup role must remain encrypt-only"
    description = (
        "The CISO segregation-of-duties design requires the backup workload "
        "to be write-only: it must never hold s3:GetObject, s3:ListBucket or "
        "kms:Decrypt, including via wildcard grants (s3:*, kms:*, s3:Get*). "
        "All IAM resources in the template are scanned (fail-closed): scoping "
        "by resource name would let a renamed or new role slip through. "
        "NOTE: do NOT set self.severity in __init__ - it is a read-only "
        "property in modern cfn-lint and raises AttributeError, which "
        "silently prevents the rule from loading at all."
    )
    source_url = "https://internal-wiki/SoD-backup-role"
    tags = ["iam", "security", "sod", "least-privilege"]

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

    def match(self, cfn):
        matches = []
        resources = cfn.template.get("Resources", {})
        for logical_id, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            if resource.get("Type") not in IAM_RESOURCE_TYPES:
                continue
            properties = resource.get("Properties", {})
            if not isinstance(properties, dict):
                continue
            base = ["Resources", logical_id, "Properties"]

            # Inline policies on Role: Policies[].PolicyDocument
            for p_idx, policy in enumerate(properties.get("Policies", []) or []):
                if isinstance(policy, dict):
                    matches.extend(
                        self._policy_document_violations(
                            policy.get("PolicyDocument", {}),
                            base + ["Policies", p_idx, "PolicyDocument"],
                        )
                    )

            # Standalone Policy / ManagedPolicy: PolicyDocument at top level
            matches.extend(
                self._policy_document_violations(
                    properties.get("PolicyDocument", {}),
                    base + ["PolicyDocument"],
                )
            )
        return matches
