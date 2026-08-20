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
import io
import json
import logging
import os
import zipfile
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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

# SES delivers the certificate as a real .crt attachment - SNS email is
# plain-text only and cannot carry attachments. Both must be set for the
# attachment email to send; if either is missing, set_secret falls back to
# an SNS text notice with the cert pasted inline (degraded but not silent).
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL", "")
ALERT_EMAIL_ADDRESS = os.environ.get("ALERT_EMAIL_ADDRESS", "")
POLL_RULE_NAME = os.environ.get("POLL_RULE_NAME", "")

# Field names - single source of truth, must match salesforce_backup.py
F_CONSUMER_KEY = "sf_consumer_key"
F_PRIVATE_KEY = "sf_jwt_private_key"
F_PENDING_CERT = "_pending_public_cert"

# Secret tag used to make setSecret's notification idempotent: Secrets
# Manager retries an INCOMPLETE rotation on its own schedule (testSecret
# keeps failing until the certificate is uploaded by hand), and each retry
# re-invokes setSecret. Without this guard, every retry would resend the
# certificate email.
TAG_NOTIFIED_VERSION = "CertNotifiedForVersion"

_clients: dict = {}


def _client(name: str):
    """Lazy, cached boto3 clients - keeps cold starts lean and imports testable."""
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


def notify(subject: str, message: str) -> None:
    """Plain-text SNS notice. Used for completion/rollback alerts, which
    happen once at a terminal state and need no attachment."""
    logger.info("NOTIFY: %s", subject)
    if SNS_TOPIC_ARN:
        try:
            _client("sns").publish(
                TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message
            )
        except Exception:
            logger.exception("SNS publish failed (continuing)")


def send_cert_email(cert_pem: str) -> None:
    """Deliver the new certificate as a .crt file inside a .zip via SES.

    SES's SendRawEmail rejects several uncommon-but-harmless extensions
    with "Illegal filename" - confirmed empirically against this account
    for .crt (and documented for others such as .pem, .key, .cer). .zip is
    an accepted extension, and zipping means the admin gets the correctly
    named SF_Backup_S3.crt file back out - no manual rename step.

    SNS email is plain text only - it cannot carry attachments at all,
    which is why the certificate was previously pasted inline as text.
    Falls back to that SNS text notice if SES sender/recipient are not
    configured, so the admin still gets *something* rather than silence.
    """
    if not (SES_SENDER_EMAIL and ALERT_EMAIL_ADDRESS):
        logger.warning(
            "SES_SENDER_EMAIL or ALERT_EMAIL_ADDRESS not set - falling back "
            "to SNS text notice with the certificate pasted inline"
        )
        notify(
            f"ACTION REQUIRED: upload new certificate for {SF_ECA_FULLNAME}",
            f"SES not configured, sending certificate inline instead of as "
            f"an attachment.\n\n{cert_pem}",
        )
        return

    cert_filename = f"{SF_ECA_FULLNAME}.crt"
    zip_filename = f"{SF_ECA_FULLNAME}.zip"

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(cert_filename, cert_pem)
    zip_bytes = zip_buffer.getvalue()

    msg = MIMEMultipart()
    msg["Subject"] = f"ACTION REQUIRED: upload new certificate for {SF_ECA_FULLNAME}"
    msg["From"] = SES_SENDER_EMAIL
    msg["To"] = ALERT_EMAIL_ADDRESS
    msg.attach(
        MIMEText(
            f"""A new JWT keypair has been generated for the Salesforce backup.

The OLD key still works - backups are unaffected until you complete the
step below.

Upload the certificate in Salesforce Setup:
  a) Unzip the attachment ({zip_filename}) to get {cert_filename}
  b) External Client App Manager -> {SF_ECA_FULLNAME} -> OAuth Settings
     -> Use digital signatures -> upload {cert_filename}

That is the only step needed. The backup system checks automatically
every 30 minutes and switches over to the new key on its own as soon as
the upload is detected - no further action, no AWS CLI command to run.
"""
        )
    )
    attachment = MIMEApplication(zip_bytes, _subtype="zip")
    attachment.add_header("Content-Disposition", "attachment", filename=zip_filename)
    msg.attach(attachment)

    try:
        _client("ses").send_raw_email(
            Source=SES_SENDER_EMAIL,
            Destinations=[ALERT_EMAIL_ADDRESS],
            RawMessage={"Data": msg.as_string()},
        )
        logger.info(
            "send_cert_email: certificate delivered as .crt inside a .zip via SES"
        )
    except Exception:
        logger.exception("SES send failed - falling back to SNS text notice")
        notify(
            f"ACTION REQUIRED: upload new certificate for {SF_ECA_FULLNAME}",
            f"SES delivery failed, sending certificate inline instead.\n\n{cert_pem}",
        )


def _already_notified(arn: str, token: str) -> bool:
    """True if setSecret already sent the certificate email for this
    AWSPENDING version. Secrets Manager retries an incomplete rotation on
    its own schedule, and each retry re-invokes setSecret - without this
    guard every retry would resend the same email."""
    tags = _client("secretsmanager").describe_secret(SecretId=arn).get("Tags", []) or []
    return any(t["Key"] == TAG_NOTIFIED_VERSION and t["Value"] == token for t in tags)


def _mark_notified(arn: str, token: str) -> None:
    _client("secretsmanager").tag_resource(
        SecretId=arn, Tags=[{"Key": TAG_NOTIFIED_VERSION, "Value": token}]
    )


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


# --------------------------------------------------------------------------
# Self-poll: while a rotation waits on the manual certificate upload, an
# EventBridge schedule re-invokes rotate-secret every 30 minutes so the
# rotation completes on its own shortly after the upload, instead of
# depending on someone remembering to run `rotate-secret` by hand.
# The rule starts DISABLED (see template.yaml) - set_secret enables it,
# finish_secret disables it. Both toggles are best-effort: a failure here
# must never break the rotation itself, only the auto-resume convenience.
# --------------------------------------------------------------------------
def _enable_poll_rule() -> None:
    if not POLL_RULE_NAME:
        return
    try:
        _client("events").enable_rule(Name=POLL_RULE_NAME)
        logger.info("Poll rule enabled - rotate-secret will retry every 30 min")
    except Exception:
        logger.exception("Failed to enable poll rule (continuing)")


def _disable_poll_rule() -> None:
    if not POLL_RULE_NAME:
        return
    try:
        _client("events").disable_rule(Name=POLL_RULE_NAME)
        logger.info("Poll rule disabled - nothing pending")
    except Exception:
        logger.exception("Failed to disable poll rule (continuing)")


def poll_rotation(secret_arn: str) -> None:
    """EventBridge poll target. Safety guard is deliberate: calling
    rotate-secret when NOTHING is pending would start a brand-new,
    unwanted rotation cycle on a healthy secret. Only re-trigger when an
    AWSPENDING version actually exists; otherwise self-disable and exit -
    covers the case where finish_secret's disable call failed earlier."""
    meta = _client("secretsmanager").describe_secret(SecretId=secret_arn)
    stages = meta.get("VersionIdsToStages", {})
    if not any("AWSPENDING" in s for s in stages.values()):
        logger.info("pollRotation: nothing pending - disabling poll rule")
        _disable_poll_rule()
        return
    _client("secretsmanager").rotate_secret(SecretId=secret_arn)
    logger.info("pollRotation: rotate-secret re-triggered")


def set_secret(arn: str, token: str) -> None:
    """Hand the new PUBLIC certificate to the admin. Salesforce is untouched.

    Idempotent: Secrets Manager retries an incomplete rotation on its own
    schedule (testSecret keeps failing until the admin uploads the cert),
    and each retry re-invokes setSecret. Skip re-sending if this token's
    certificate email already went out.
    """
    # Still waiting on the manual step regardless of whether this call sends
    # a fresh email - keep the poll rule on (idempotent if already enabled).
    _enable_poll_rule()

    if _already_notified(arn, token):
        logger.info(
            "setSecret: certificate email already sent for this version - "
            "skipping duplicate (rotation is waiting on the manual upload)"
        )
        return

    pending = get_secret_dict(arn, "AWSPENDING", token)
    cert_pem = pending[F_PENDING_CERT]

    send_cert_email(cert_pem)
    _mark_notified(arn, token)
    logger.info("setSecret: certificate published for manual upload")


def test_secret(arn: str, token: str) -> None:
    """Verify the pending key. Expected to fail until the admin uploads the cert."""
    pending = get_secret_dict(arn, "AWSPENDING", token)
    try:
        session = jwt_login(pending[F_CONSUMER_KEY], pending[F_PRIVATE_KEY])
    except RuntimeError as auth_error:
        # The designed hand-off point: no certificate uploaded yet. The
        # EventBridge poll (enabled by setSecret) will retry this
        # automatically every 30 minutes - no manual re-run needed once
        # the certificate is uploaded.
        raise RuntimeError(
            f"testSecret: the pending key cannot authenticate yet. This is "
            f"expected until the new certificate is uploaded to "
            f"{SF_ECA_FULLNAME} in Salesforce Setup. The poll will retry "
            f"automatically once that happens. Underlying error: {auth_error}"
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

    # Moving AWSCURRENT does NOT auto-remove AWSPENDING from the same
    # version - the two labels are independent API calls. Without this,
    # the promoted version stays tagged AWSPENDING forever (confirmed
    # against a documented gap in AWS's own rotation-lambda samples,
    # aws-samples/aws-secrets-manager-rotation-lambdas#168).
    try:
        _client("secretsmanager").update_secret_version_stage(
            SecretId=arn, VersionStage="AWSPENDING", RemoveFromVersionId=token
        )
    except _client("secretsmanager").exceptions.InvalidParameterException:
        # AWSPENDING was already absent (e.g. a resumed/manual finishSecret
        # call) - nothing to remove, not an error.
        logger.info("finishSecret: AWSPENDING already absent on this version")

    notify(
        f"Rotation completed for {SF_ECA_FULLNAME}",
        f"The new JWT private key is now AWSCURRENT for {arn}.\n\n"
        f"The previous key is retained as AWSPREVIOUS but no longer works: the "
        f"certificate it matched has been replaced in Salesforce.",
    )
    _disable_poll_rule()
    logger.info("finishSecret: new key promoted to AWSCURRENT, AWSPENDING cleared")


def lambda_handler(event, context):
    # EventBridge poll target - distinct payload shape from Secrets
    # Manager's own rotation-step invocations (which always carry "Step").
    if event.get("Action") == "poll_rotation":
        poll_rotation(event["SecretArn"])
        return

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
