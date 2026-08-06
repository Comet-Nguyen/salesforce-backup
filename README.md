# Salesforce → Amazon S3 Backup

Daily backup of Salesforce (Sales Cloud + Pardot/Account Engagement) to
Amazon S3, orchestrated by AWS Step Functions and designed for ISO 27001
Segregation-of-Duties: **the backup workload can write backups but can never
read or decrypt them.**

## Architecture overview

Orchestration is AWS Step Functions (Architect decision). One Lambda serves
every stage through `step_handler`, which dispatches on `event["action"]` -
so all stages share one codebase, one deployment artifact and one
encrypt-only IAM role.

```
EventBridge (cron 01:00 UTC, Input {"mode": null} → weekday decides mode)
      │
      ▼
Step Functions state machine: salesforce-backup-<env>
      │
      ├─ Discover ──── JWT auth, customer-scoped standard objects +
      │                auto-discovered custom objects (__c) via Describe API
      │
      ├─ ExportAll (Parallel)
      │     ├─ Map over objects, MaxConcurrency 6
      │     │     └─ ExportOne → Bulk API 2.0, REST fallback (Quote)
      │     │        Catch → MarkFailed (one object never fails the run)
      │     └─ ExportPardot → Pardot API v5, cursor pagination
      │
      └─ Aggregate ─── execution log JSON → S3, HTML email via SES,
                       SNS alerts, CloudWatch volume metrics
      │
      ▼
S3 bucket (Object Lock COMPLIANCE, versioning, deny-GetObject to ops roles)
encrypted with a KMS key held in a separate shared-services account
```

Each stage uploads with `s3:PutObject` + SSE-KMS + SHA256 checksum; no stage
ever reads an object back.

Mode: incremental daily (`LastModifiedDate`/`SystemModstamp = LAST_N_DAYS:1`),
full every Saturday. High-volume/low-restore-value objects (Pardot
Visitor/VisitorActivity) are deferred to the weekly full run.

### Why Step Functions

Both options were built and measured on the same workload (lab, 15 objects):
Lambda monolith ~41s, Step Functions ~70s - the fan-out pays a per-worker
cold start, re-auth and re-describe. Step Functions was chosen anyway for
operational reasons: a visual per-object execution graph, native retry and
catch semantics per stage, and headroom to grow past a single 15-minute
Lambda budget. The `execution_log_*.json` on S3 remains the durable audit
record (execution history expires after 90 days).

The Dockerfile kept outside the repository is the pre-built Fargate exit
plan, to be adopted if a single export ever outgrows the Lambda timeout.

## Security controls (CISO review mapping)

| Control | Implementation |
|---|---|
| SoD: encrypt-only workload role | IAM grants `s3:PutObject` + `kms:GenerateDataKey` only. No `GetObject`, no `Decrypt`. CI rule E9001 fails any PR that reintroduces them, including via wildcards (`s3:*`, `kms:*`, `s3:Get*`). |
| Cross-account key custody | The KMS key lives in the shared-services account; the workload account holds `GenerateDataKey` + `DescribeKey` only. Even an account-local bucket-policy change cannot yield plaintext. |
| Externally managed KMS & bucket | `template.yaml` takes `KMSKeyArn` / `S3BucketArn` as parameters; the stack creates neither. |
| Integrity without read-back | `ChecksumAlgorithm=SHA256` on every PutObject - S3 validates server-side and rejects corrupted uploads. |
| Anomaly detection without data access | 7-day volume history lives in CloudWatch custom metrics (`SalesforceBackup/TotalRows`, counts only - no PII). ±30% deviation alerts via SNS + email. |
| Secret scoping | `secretsmanager:GetSecretValue` on the exact secret ARN, no wildcards. |
| 180-day rotation | `AWS::SecretsManager::RotationSchedule` - certificate uploaded manually, rotation self-completes via an EventBridge poll (see below). |
| Immutability / ransomware | Object Lock Compliance + versioning + CloudTrail data events. Re-runs create new versions, never overwrite in place. |
| No static AWS keys in CI | GitHub OIDC role assumption, trust policy pinned to `repo:<owner>/<repo>:environment:<env>`. |

Verified in the lab, with evidence captured:

| Action | Workload account (ops) | Shared-services account (data owner) |
|---|---|---|
| Write backup | allowed | - |
| Read backup | **AccessDenied** (explicit deny in bucket policy - applies even to AdministratorAccess) | allowed |
| Delete before retention | **AccessDenied** (Object Lock) | **AccessDenied** (Object Lock) |
| `s3:GetObject` / `kms:Decrypt` for the backup role | **implicitDeny** (IAM Policy Simulator) | - |

### JWT certificate rotation (manual upload, self-completing)

Salesforce team decision: the certificate is uploaded to the External
Client App **by hand**, not deployed via the Metadata API. Rotation is a
two-phase process where phase 2 normally needs a human - except a
self-poll mechanism closes that gap automatically.

**Phase 1 - automatic, on schedule (every `RotationIntervalDays`):**

1. `createSecret` - generates RSA-2048 + a 365-day self-signed certificate,
   staged as AWSPENDING
2. `setSecret` - emails the new certificate as a real **.crt attachment**
   via SES (SNS email is plain text only and cannot carry attachments),
   and enables the poll schedule below. Salesforce is not touched - the
   **old key keeps working**, so backups are unaffected
3. `testSecret` - fails by design: the old certificate is still installed
   in Salesforce, so the pending key cannot authenticate yet

**Phase 2 - after the admin uploads the certificate in Setup:**

An EventBridge schedule (`rate(30 minutes)`, disabled by default) re-invokes
`rotate-secret` while a rotation is waiting. The moment the certificate is
uploaded, the next poll's `testSecret` passes and `finishSecret` promotes
the new key - **no one needs to remember to run `rotate-secret` by hand.**
The poll is enabled by `setSecret` and disabled by `finishSecret`, and
carries a safety guard: if invoked with nothing actually pending (e.g. a
disable call failed earlier), it disables itself and does **not** call
`rotate-secret` - calling that API with no pending rotation would start an
unwanted new cycle on an otherwise healthy secret.

Two further details worth knowing:

- **Idempotent notification.** Secrets Manager retries an incomplete
  rotation on its own schedule in addition to the poll, and each retry
  re-invokes `setSecret`. A tag on the secret (`CertNotifiedForVersion`)
  ensures the certificate email is sent once per generated keypair, not
  once per retry.
- **`AWSPENDING` cleanup.** Moving the `AWSCURRENT` label to the new
  version does **not** automatically remove `AWSPENDING` from it - these
  are two independent Secrets Manager API calls (a gap documented against
  AWS's own rotation-lambda samples,
  `aws-samples/aws-secrets-manager-rotation-lambdas#168`). `finishSecret`
  removes it explicitly; without that fix the promoted version stays
  tagged `AWSPENDING` forever.

Rotation interval: **180 days in PRD** (CISO-confirmed - supersedes the
90-day figure in the original SecurityRequirements doc), **1 day in UAT**
to exercise the flow quickly in the lab.

## Repository layout

```
template.yaml                        SAM: Lambda + state machine + schedule
src/backup/{salesforce_backup.py, requirements.txt}
src/rotation/{rotation_function.py, requirements.txt}
.github/workflows/{ci.yml, deploy.yml, sam-deploy.yml, security-scan.yml}
.github/cfn-lint-rules/sod_backup_role.py     custom rule E9001
.trivyignore                         documented, time-bound CVE exceptions
README.md
```

`sam-deploy.yml` is a repo-local reusable workflow written in LZv2
conventions; when the platform team publishes the org-standard version,
`deploy.yml` switches its `uses:` reference in one line.

## CI/CD

```
feature branch → PR → CI → review → merge develop → auto-deploy UAT
                                  → merge main → workflow_dispatch
                                    → required reviewer → deploy PRD
```

CI jobs on every pull request:

| Job | Purpose |
|---|---|
| SAM validate + cfn-lint | Template validation (`sam validate --lint` runs cfn-lint without AWS credentials, so it fails fast before any account is touched) |
| Lint & Test (Ruff) | `ruff check`, `ruff format --check`, `py_compile`, pytest when `tests/` exists |
| Policy-as-Code (Checkov) | Informational IaC findings (soft-fail) |
| SoD guard (E9001) | Blocking. Structure-aware custom cfn-lint rule; scans every IAM resource fail-closed rather than filtering by name |
| Secrets Detection (gitleaks) | Credentials in code. The LZv2 security-scan workflow does **not** cover this despite the name |
| LZv2 Security Scan | Org-standard reusable workflow: pip-audit CVE scan. Its Docker jobs skip when `dockerfile_path` is empty |

### Variable scope (a real constraint, worth knowing before refactoring)

A job that calls a reusable workflow **cannot declare `environment:`**, and
expressions in its `with:` block are evaluated in the caller context, where
no environment is selected. Environment-scoped variables therefore resolve
to empty strings there. With the thin-caller pattern all variables must be
**repository-level with `_UAT` / `_PRD` suffixes**. The `prd` reviewer gate
is unaffected: `sam-deploy.yml` declares `environment: prd` on the job that
actually deploys.

Repository variables: `AWS_DEPLOY_ROLE_*`, `KMS_KEY_ARN_*`, `S3_BUCKET_ARN_*`,
`SF_USERNAME_*`, `SF_LOGIN_URL_*`, `AWS_REGION_*`, `SAM_ARTIFACT_BUCKET_*`.
All are ARNs or identifiers - no secrets are stored in GitHub.

### One-time AWS setup per environment

1. OIDC provider `token.actions.githubusercontent.com` in the workload
   account (SSO permission-set roles cannot be assumed by GitHub Actions -
   CI needs its own role).
2. Deploy role per environment, trust policy pinned to the exact `sub`
   claim. GitHub appends numeric owner and repository IDs to that claim
   (`repo:<owner>@<ownerId>/<repo>@<repoId>:environment:<env>`); read the
   real value from CloudTrail or by printing the token claims once, rather
   than assuming the documented short form.
3. Deploy-role permissions scoped to `salesforce-backup-*`, including
   `cloudformation:CreateChangeSet` on
   `arn:aws:cloudformation:<region>:aws:transform/Serverless-2016-10-31`,
   `states:*` on the state machine, and `iam:PassRole` conditioned to
   `lambda`, `states` and `events`.
4. A dedicated SAM artifacts bucket (lifecycle 30 days). `--resolve-s3`
   would need permission to create its own bucket and stack, outside the
   scoped policy.

## First-run checklist per environment

1. Confirm the KMS key policy allows this account `kms:GenerateDataKey`, and
   the bucket policy allows the data-owner account to read.
2. Load credentials into the secret through a secure channel, never git/CI.
   Field names must match exactly: **`sf_consumer_key`**,
   **`sf_jwt_private_key`**, `pardot_*`. On Windows use
   `Get-Content -Raw` - without it PowerShell yields an array of lines,
   which serializes to a JSON array and fails with *Expecting a
   PEM-formatted key*.
3. Verify the SES sender identity (DKIM) in the target region.
4. Start one execution manually with `{"mode": "incremental"}` and read the
   graph before enabling the schedule.
5. Confirm: CSV objects in S3, `execution_log_*.json`, email report.
   Verify from the **data-owner** account - an AccessDenied from the
   workload account is the control working, not a fault.

## Operations

| Task | How |
|---|---|
| On-demand run | `aws stepfunctions start-execution --input '{"mode":"full"}'` |
| Per-object status | Execution graph, or `execution_log_*.json` in S3 (durable beyond the 90-day execution history) |
| Adjust scope / concurrency | `EXPORT_SCOPE`, `WEEKLY_ONLY_OBJECTS` env vars; `MaxConcurrency` in the Map state |
| Enable Pardot | Set `PARDOT_CLIENT_ID`, `PARDOT_BUSINESS_UNIT_ID` (UAT and production business units have different IDs) plus the `pardot_*` secret fields |
| Duration early-warning | CloudWatch alarm at 600s; three consecutive breaches trigger the documented Fargate migration |
| Restore | Data-owner account only: download the version, verify row counts against the execution log, import with Data Loader upsert on External Id |
| Pause the backup schedule | `aws events disable-rule --name salesforce-backup-sfn-daily-<env>` |
| Force a rotation retry now (skip the 30-min poll wait) | `aws secretsmanager rotate-secret --secret-id salesforce-backup-<env>/credentials` |
| Rotation stuck / poll misbehaving | `aws events disable-rule --name salesforce-backup-rotation-poll-<env>` - safe any time, `setSecret` re-enables it on the next scheduled rotation |

## Known gaps

- Log retention beyond 90 days is not yet configured.
- `COUNT()` reconciliation between Salesforce and exported rows is not yet
  implemented; row counts are currently self-reported by the exporter.
- Pardot still uses the password-based flow. Migrating to
  `client_credentials` (with `shouldRotateConsumerSecret`) would make Pardot
  credential rotation fully automatic and remove the security-token
  deadlock; the change is roughly five lines in `get_pardot_token()`.
- In the lab, an administrator of the workload account can still edit the
  bucket policy. Production relies on Landing Zone SCPs to close this;
  the KMS key custody in a separate account remains the backstop.