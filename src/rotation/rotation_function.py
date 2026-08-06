"""Secrets Manager rotation Lambda - JWT key rotation, MANUAL certificate upload.

Design decision (Salesforce team): the public certificate is uploaded to the
External Client App by hand, not deployed through the Metadata API. Rotation is
therefore a TWO-PHASE process, and the first pass is EXPECTED to stop at
testSecret:

  Phase 1 - automatic, on schedule
    createSecret : generate RSA-2048 + self-signed X.509 (365d) -> AWSPENDING
    setSecret    : publish the new PUBLIC certificate over SNS for the admin.
                   Salesforce is NOT touched here - nothing to roll back.
    testSecret   : JWT auth with the pending key -> FAILS while the old
                   certificate is still the one installed. This failure is the
                   designed hand-off point, not a defect.

  Phase 2 - after the admin uploads the certificate in Setup
    Re-trigger:  aws secretsmanager rotate-secret --secret-id <arn>
    testSecret   : now succeeds
    finishSecret : promote AWSPENDING -> AWSCURRENT, notify

Why this ordering is safe: the OLD private key keeps working until the moment
the admin replaces the certificate in Salesforce, so backups never break
mid-rotation. The window of exposure is between the manual upload and
finishSecret promoting the new key - keep it short by re-triggering promptly.

Secret JSON (field names MUST match salesforce_backup.py exactly):
  {
    "sf_consumer_key":    "...",             # unchanged by rotation
    "sf_jwt_private_key": "-----BEGIN ...",  # ROTATED
    "_pending_public_cert": "-----BEGIN CERTIFICATE-----..."   # work field
  }
Any other keys (pardot_*) are carried through untouched.
"""

import datetime
import json
import logging
import os

import boto3
import jwt  # PyJWT[crypto]
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logging.basicConfig(
    level=logging.INFO, force=True
)  # force: Lambda pre-configures handlers
logger = logging.getLogger(__name__)

SF_LOGIN_URL = os.environ.get("SF_LOGIN_URL", "https://login.salesforce.com")
SF_USERNAME = os.environ["SF_USERNAME"]
SF_ECA_FULLNAME = os.environ.get("SF_ECA_FULLNAME", "SF_Backup_S3")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
CERT_VALIDITY_DAYS = int(os.environ.get("CERT_VALIDITY_DAYS", "365"))

# Field names - single source of truth, must match salesforce_backup.py
F_CONSUMER_KEY = "sf_consumer_key"
F_PRIVATE_KEY = "sf_jwt_private_key"
F_PENDING_CERT = "_pending_public_cert"

_clients: dict = {}


def _client(name: str):
    """Lazy, cached boto3 clients - keeps cold starts lean and imports testable."""
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


def notify(subject: str, message: str) -> None:
    logger.info("NOTIFY: %s", subject)
    if SNS_TOPIC_ARN:
        try:
            _client("sns").publish(
                TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message
            )
        except Exception:
            logger.exception("SNS publish failed (continuing)")


def jwt_login(consumer_key: str, private_key_pem: str) -> dict:
    """JWT Bearer flow. Returns {'access_token','instance_url'}; raises on failure."""
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    assertion = jwt.encode(
        {
            "iss": consumer_key,
            "sub": SF_USERNAME,
            "aud": SF_LOGIN_URL,
            "exp": now + 300,
        },
        private_key_pem,
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
        raise RuntimeError(f"JWT auth failed ({resp.status_code}): {resp.text[:300]}")
    return resp.json()


def generate_keypair_and_cert() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SF_ECA_FULLNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .sign(key, hashes.SHA256())
    )
    return private_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


def get_secret_dict(arn: str, stage: str, token: str | None = None) -> dict:
    kwargs = (
        {"SecretId": arn, "VersionId": token}
        if token
        else {"SecretId": arn, "VersionStage": stage}
    )
    return json.loads(
        _client("secretsmanager").get_secret_value(**kwargs)["SecretString"]
    )


# --------------------------------------------------------------------------
# Rotation steps
# --------------------------------------------------------------------------
def create_secret(arn: str, token: str) -> None:
    try:
        get_secret_dict(arn, "AWSPENDING", token)
        logger.info("createSecret: AWSPENDING already exists - idempotent skip")
        return
    except _client("secretsmanager").exceptions.ResourceNotFoundException:
        pass

    current = get_secret_dict(arn, "AWSCURRENT")
    if F_CONSUMER_KEY not in current:
        raise RuntimeError(
            f"AWSCURRENT is missing '{F_CONSUMER_KEY}'. The secret must be seeded "
            f"with {F_CONSUMER_KEY} and {F_PRIVATE_KEY} before rotation can run."
        )

    private_pem, cert_pem = generate_keypair_and_cert()
    pending = dict(current)  # carry through consumer key, pardot_* fields, etc.
    pending[F_PRIVATE_KEY] = private_pem
    pending[F_PENDING_CERT] = cert_pem
    _client("secretsmanager").put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(pending),
        VersionStages=["AWSPENDING"],
    )
    logger.info("createSecret: new keypair staged as AWSPENDING")


def set_secret(arn: str, token: str) -> None:
    """Hand the new PUBLIC certificate to the admin. Salesforce is untouched."""
    pending = get_secret_dict(arn, "AWSPENDING", token)
    cert_pem = pending[F_PENDING_CERT]

    notify(
        f"ACTION REQUIRED: upload new certificate for {SF_ECA_FULLNAME}",
        f"""A new JWT keypair has been generated for the Salesforce backup.

The OLD key still works - backups are unaffected until you complete step 1.

STEP 1 - Upload the certificate (Salesforce Setup)
  External Client App Manager -> {SF_ECA_FULLNAME} -> OAuth Settings
  -> Use digital signatures -> upload the certificate below.

STEP 2 - Complete the rotation (AWS CLI)
  aws secretsmanager rotate-secret --secret-id {arn}

  This re-runs the rotation, which will now verify the new key and promote
  it to AWSCURRENT. Until you do this, the backup keeps using the old key,
  which stops working the moment step 1 replaces the certificate - so run
  step 2 immediately after step 1.

Certificate to upload (public - safe to email):

{cert_pem}
""",
    )
    logger.info("setSecret: certificate published for manual upload")


def test_secret(arn: str, token: str) -> None:
    """Verify the pending key. Expected to fail until the admin uploads the cert."""
    pending = get_secret_dict(arn, "AWSPENDING", token)
    try:
        session = jwt_login(pending[F_CONSUMER_KEY], pending[F_PRIVATE_KEY])
    except RuntimeError as auth_error:
        # The designed hand-off point: no certificate uploaded yet.
        raise RuntimeError(
            f"testSecret: the pending key cannot authenticate yet. This is "
            f"expected until the new certificate is uploaded to "
            f"{SF_ECA_FULLNAME} in Salesforce Setup. After uploading, re-run: "
            f"aws secretsmanager rotate-secret --secret-id {arn}. "
            f"Underlying error: {auth_error}"
        ) from auth_error

    # Beyond token issuance, prove the session works for real API calls.
    resp = requests.get(
        f"{session['instance_url']}/services/data/",
        headers={"Authorization": f"Bearer {session['access_token']}"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"testSecret: API smoke call failed ({resp.status_code})")
    logger.info("testSecret: pending key authenticates and is usable")


def finish_secret(arn: str, token: str) -> None:
    meta = _client("secretsmanager").describe_secret(SecretId=arn)
    current_version = None
    for version_id, stages in meta.get("VersionIdsToStages", {}).items():
        if "AWSCURRENT" in stages:
            if version_id == token:
                logger.info("finishSecret: already AWSCURRENT - idempotent skip")
                return
            current_version = version_id
            break

    _client("secretsmanager").update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    notify(
        f"Rotation completed for {SF_ECA_FULLNAME}",
        f"The new JWT private key is now AWSCURRENT for {arn}.\n\n"
        f"The previous key is retained as AWSPREVIOUS but no longer works: the "
        f"certificate it matched has been replaced in Salesforce.",
    )
    logger.info("finishSecret: new key promoted to AWSCURRENT")


def lambda_handler(event, context):
    step, arn, token = event["Step"], event["SecretId"], event["ClientRequestToken"]
    logger.info("Rotation step=%s secret=%s", step, arn)

    meta = _client("secretsmanager").describe_secret(SecretId=arn)
    if not meta.get("RotationEnabled", False):
        raise ValueError(f"Rotation not enabled for {arn}")
    stages = meta["VersionIdsToStages"].get(token, [])
    if "AWSCURRENT" in stages:
        logger.info("Version already AWSCURRENT - nothing to do")
        return
    if "AWSPENDING" not in stages:
        raise ValueError(f"Version {token} not staged AWSPENDING for {arn}")

    {
        "createSecret": create_secret,
        "setSecret": set_secret,
        "testSecret": test_secret,
        "finishSecret": finish_secret,
    }[step](arn, token)
