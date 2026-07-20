"""Secrets Manager rotation function - Salesforce JWT private key (90-day).

Semi-automated by necessity: a JWT keypair rotation is only complete when the
NEW PUBLIC CERTIFICATE has been uploaded to the Salesforce External Client
App, which no AWS service can do on its own. The standard 4-step rotation
protocol is used, with the human step embedded in the retry loop:

  createSecret : generate a new RSA-2048 keypair; store the full secret JSON
                 (new private key, all other fields carried over) as the
                 AWSPENDING version.
  setSecret    : publish the new PUBLIC certificate (PEM) to SNS so the
                 Salesforce admin can upload it to the External Client App.
                 Idempotent - re-notifies on retries.
  testSecret   : attempt a real JWT OAuth token exchange against Salesforce
                 using the PENDING private key. FAILS until the admin has
                 uploaded the cert - Secrets Manager automatically retries
                 the rotation over the following hours, so this failure is
                 the designed "wait for human" gate, not an error.
  finishSecret : promote AWSPENDING to AWSCURRENT. The backup function picks
                 up the new key on its next run (SecretsStore reads at
                 runtime, no cache across invocations).

The old certificate should be removed from the External Client App after one
successful backup run on the new key.
"""

import json
import logging
import os
import time

import boto3
import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

logging.basicConfig(level="INFO", force=True)
logger = logging.getLogger("rotation")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
SF_LOGIN_URL = os.environ["SF_LOGIN_URL"]
SF_USERNAME = os.environ["SF_USERNAME"]


def lambda_handler(event, context):  # noqa: ANN001, ARG001
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    sm = boto3.client("secretsmanager")

    metadata = sm.describe_secret(SecretId=arn)
    versions = metadata.get("VersionIdsToStages", {})
    if token not in versions:
        raise ValueError(f"Version {token} not found for secret {arn}")
    if "AWSCURRENT" in versions[token]:
        logger.info("Version %s already AWSCURRENT - nothing to do", token)
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError(f"Version {token} not staged AWSPENDING for {arn}")

    if step == "createSecret":
        _create_secret(sm, arn, token)
    elif step == "setSecret":
        _set_secret(sm, arn, token)
    elif step == "testSecret":
        _test_secret(sm, arn, token)
    elif step == "finishSecret":
        _finish_secret(sm, arn, token)
    else:
        raise ValueError(f"Unknown rotation step: {step}")


def _create_secret(sm, arn: str, token: str) -> None:
    """Generate a new keypair; carry every non-key field over unchanged."""
    try:
        sm.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: pending version already exists - idempotent skip")
        return
    except sm.exceptions.ResourceNotFoundException:
        pass

    current = json.loads(
        sm.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"]
    )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Self-signed cert for the Salesforce External Client App (JWT Bearer)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sf-backup-rotated")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=180))
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    pending = dict(current)
    pending["sf_jwt_private_key"] = private_pem
    pending["_pending_public_cert"] = cert_pem  # consumed by setSecret notification

    sm.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(pending),
        VersionStages=["AWSPENDING"],
    )
    logger.info("createSecret: new RSA-2048 keypair staged as AWSPENDING")


def _set_secret(sm, arn: str, token: str) -> None:
    """Human gate: send the new public cert to the Salesforce admin."""
    pending = json.loads(
        sm.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")[
            "SecretString"
        ]
    )
    cert_pem = pending.get("_pending_public_cert", "")
    boto3.client("sns").publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[ACTION REQUIRED] Salesforce backup JWT key rotation - upload new certificate",
        Message=(
            "A 90-day rotation of the Salesforce backup JWT key has started.\n\n"
            "ACTION: upload the certificate below to the External Client App\n"
            "(App Manager > SF_Backup_S3 > Settings > JWT Bearer Flow > Certificate),\n"
            "keeping the OLD certificate in place until rotation completes.\n\n"
            "Rotation will verify automatically and finalize once the cert is live.\n"
            "Remove the old certificate after the next successful backup run.\n\n"
            f"{cert_pem}"
        ),
    )
    logger.info("setSecret: admin notified with new public certificate")


def _test_secret(sm, arn: str, token: str) -> None:
    """Real JWT auth with the PENDING key. Failure here is the designed
    wait-for-human gate - Secrets Manager retries until the cert is uploaded."""
    pending = json.loads(
        sm.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")[
            "SecretString"
        ]
    )
    consumer_key = pending.get("sf_consumer_key", "").strip()
    if not consumer_key:
        raise RuntimeError("testSecret: sf_consumer_key missing from pending secret")

    assertion = jwt.encode(
        {
            "iss": consumer_key,
            "sub": SF_USERNAME,
            "aud": SF_LOGIN_URL,
            "exp": int(time.time()) + 300,
        },
        pending["sf_jwt_private_key"],
        algorithm="RS256",
    )
    resp = requests.post(
        f"{SF_LOGIN_URL}/services/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"testSecret: JWT auth with pending key not yet accepted "
            f"({resp.status_code}: {resp.text[:200]}). Expected until the new "
            f"certificate is uploaded to Salesforce - rotation will retry."
        )
    logger.info("testSecret: pending key authenticated successfully")


def _finish_secret(sm, arn: str, token: str) -> None:
    metadata = sm.describe_secret(SecretId=arn)
    current_version = next(
        (
            v
            for v, stages in metadata["VersionIdsToStages"].items()
            if "AWSCURRENT" in stages
        ),
        None,
    )
    if current_version == token:
        logger.info("finishSecret: version already current")
        return
    sm.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    boto3.client("sns").publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="Salesforce backup JWT key rotation COMPLETED",
        Message=(
            "The rotated JWT key is now AWSCURRENT. After the next successful "
            "backup run, remove the OLD certificate from the External Client App."
        ),
    )
    logger.info("finishSecret: rotation finalized")
