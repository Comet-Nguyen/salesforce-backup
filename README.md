# Salesforce → Amazon S3 Backup

Production-grade daily backup of Salesforce (Sales Cloud + Pardot/Account
Engagement) to Amazon S3, designed for ISO 27001 Segregation-of-Duties:
**the backup system can write backups but can never read or decrypt them.**

## Architecture overview

```
EventBridge (cron 01:00 UTC)
      │
      ▼
Lambda: salesforce-backup  (python3.12, 900s, ENCRYPT-ONLY role)
      │  1. Auth: JWT Bearer (private key from Secrets Manager)
      │  2. Discover: customer-scoped standard objects + auto-discovered
      │     custom objects (__c) via Describe API
      │  3. Export: Bulk API 2.0 (parallel, 6 workers), REST fallback for
      │     unsupported objects (Quote); Pardot API v5 (cursor pagination)
      │  4. Upload: gzip → s3:PutObject with SSE-KMS + SHA256 checksum
      │     (server-side integrity validation - no read-back needed)
      │  5. Report: execution log JSON → S3 (put-only), HTML email via SES,
      │     SNS alerts, CloudWatch metrics (anomaly history)
      ▼
S3 bucket (CISO-provisioned: Object Lock COMPLIANCE, versioning,
           deny-GetObject bucket policy for ops roles)
```

Mode: incremental daily (`LastModifiedDate`/`SystemModstamp = LAST_N_DAYS:1`),
full every Sunday. High-volume/low-restore-value objects (Pardot
Visitor/VisitorActivity) are deferred to the weekly full run.

## Security controls (CISO review mapping)

| Control | Implementation |
|---|---|
| SoD: encrypt-only backup role | IAM grants `s3:PutObject` + `kms:GenerateDataKey` only. No `GetObject`, no `Decrypt`. CI job `encrypt-only-guard` fails any PR that reintroduces them. |
| Externally managed KMS & bucket | `template.yaml` takes `KMSKeyArn` / `S3BucketArn` as parameters; the stack creates neither. |
| Integrity without read-back | `ChecksumAlgorithm=SHA256` on every PutObject - S3 validates server-side and rejects corrupted uploads. |
| Anomaly detection without data access | 7-day volume history lives in CloudWatch custom metrics (`SalesforceBackup/TotalRows`, counts only - no PII). ±30% deviation alerts via SNS + email. |
| Secret scoping | `secretsmanager:GetSecretValue` on the exact secret ARN, no wildcards. |
| 90-day rotation | `AWS::SecretsManager::RotationSchedule` + semi-automated rotation function (see below). |
| Immutability / ransomware | Object Lock Compliance + versioning + CloudTrail data events - provisioned on the CISO side; this workload is compatible (re-runs create new versions, never overwrite-in-place). |
| No static AWS keys in CI | GitHub OIDC role assumption (`aws-actions/configure-aws-credentials`). |

### JWT key rotation (semi-automated - by necessity)

A JWT keypair rotation is only complete when the new **public certificate is
uploaded to the Salesforce External Client App** - no AWS service can perform
that step. The rotation function implements the standard 4-step protocol with
the human step inside the retry loop:

1. `createSecret` - generates a new RSA-2048 keypair, stages as AWSPENDING
2. `setSecret` - emails the new public cert to the SF admin via SNS
3. `testSecret` - attempts real JWT auth with the pending key; **fails (and
   is retried by Secrets Manager) until the admin uploads the cert** - this
   is the designed approval gate, not an error
4. `finishSecret` - promotes to AWSCURRENT; admin removes the old cert after
   the next successful backup

## Repository setup (one-time)

```bash
gh repo create tmwk-GDC/salesforce-backup --private --clone
cd salesforce-backup
# layout:
#   template.yaml
#   src/backup/{salesforce_backup.py, requirements.txt}
#   src/rotation/{rotation_function.py, requirements.txt}
#   .github/workflows/{ci.yml, deploy.yml}
#   README.md
git checkout -b develop && git push -u origin develop

# Branch protection (main and develop)
for BR in main develop; do
  gh api -X PUT "repos/tmwk-GDC/salesforce-backup/branches/$BR/protection" \
    -F required_pull_request_reviews[required_approving_review_count]=1 \
    -F required_status_checks[strict]=true \
    -f "required_status_checks[contexts][]=SAM validate + cfn-lint" \
    -f "required_status_checks[contexts][]=pip-audit (known CVEs)" \
    -f "required_status_checks[contexts][]=Secrets detection (gitleaks)" \
    -f "required_status_checks[contexts][]=SoD guard - no read-back permissions in template" \
    -F enforce_admins=true \
    -F restrictions=
done

# PRD approval gate: Settings > Environments > New environment "prd"
#   -> Required reviewers: <infra lead>  (deploy-prd job pauses here)
```

GitHub environment variables to configure (`Settings > Environments`):
`AWS_DEPLOY_ROLE_UAT/PRD` (OIDC role ARNs), `KMS_KEY_ARN_*`,
`S3_BUCKET_ARN_*` (from CISO), `SF_USERNAME_*`, `SF_LOGIN_URL_*`.

## Deployment flow

```
feature branch → PR → CI (validate, audit, gitleaks, SoD guard) → review
    → merge develop  → auto-deploy UAT
    → merge main → workflow_dispatch → required reviewer → deploy PRD
```

First-run checklist per environment:
1. CISO provides `KMSKeyArn` + `S3BucketArn`; confirm the key policy allows
   this account's backup role `kms:GenerateDataKey`.
2. Load real credentials into the secret via a secure channel (never via
   git/CI): `sf_jwt_private_key`, `sf_consumer_key`, `pardot_*`.
3. Verify SES identity `GDU_Infra_2@teamwork.net` (DKIM) in the target region.
4. Manual full run: `aws lambda invoke --payload '{"mode":"full"}' ...`
5. Confirm: objects in S3, execution log JSON, email report to
   frederic.culot@ / alexandre.raboutot@teamwork.net.

## Operations

| Task | How |
|---|---|
| On-demand full export | Invoke with payload `{"mode": "full"}` |
| Adjust scope / concurrency | Env vars `EXPORT_SCOPE`, `MAX_PARALLEL_EXPORTS`, `WEEKLY_ONLY_OBJECTS` |
| Enable Pardot | Set `PARDOT_CLIENT_ID`, `PARDOT_BUSINESS_UNIT_ID` + real `pardot_*` secret values |
| Duration early-warning | CloudWatch alarm at 600s (2/3 timeout); 3 consecutive breaches ⇒ trigger the documented Fargate migration plan |
| Restore | Data-owner team only (Frédéric): decrypt-capable role, S3 restore from version/Glacier, Data Loader import into sandbox, reconcile row counts |

# Tạo requirements
@"
simple-salesforce>=1.12,<2.0
PyJWT[crypto]>=2.8,<3.0
requests>=2.31,<3.0
"@ | Out-File src\backup\requirements.txt -Encoding ascii

@"
PyJWT[crypto]>=2.8,<3.0
requests>=2.31,<3.0
cryptography>=42.0
"@ | Out-File src\rotation\requirements.txt -Encoding ascii

@"
.aws-sam/
samconfig.toml
__pycache__/
*.pyc
.env
"@ | Out-File .gitignore -Encoding ascii