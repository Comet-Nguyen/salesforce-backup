#!/usr/bin/env python3
"""
[LAB VERSION] Salesforce (Sales Cloud) -> Amazon S3 daily backup.

Built from the production codebase; differences from prod are exactly three:
  1. Standard object list EXCLUDES Quote (Developer Edition lab org does not
     have the Quotes feature; production Enterprise org exports it via the
     REST fallback).
  2. Pardot export permanently skipped (no Pardot license in Developer
     Edition; env vars default to "skip").
  3. SES sender + notification emails hardcoded to nhikhanh28@gmail.com.

Everything else (customer scope with custom-object auto-discovery, parallel
exports via MAX_PARALLEL_EXPORTS, incremental timestamp-field selection,
REST fallback, consumer key from Secrets Manager) is identical to prod -
performance measurements in this lab are representative of production.
"""

from __future__ import annotations

import csv
import gzip
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import boto3
import jwt
import requests
from botocore.exceptions import ClientError
from simple_salesforce import Salesforce, SalesforceError
from simple_salesforce.exceptions import SalesforceOperationError

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional in Lambda; env vars are injected directly there

# --------------------------------------------------------------------------- #
# Logging (stdout - CloudWatch picks this up automatically on Lambda/ECS)
# --------------------------------------------------------------------------- #

# force=True is required on AWS Lambda: the runtime pre-installs a root
# handler, and without force basicConfig() is a no-op, leaving the level at
# WARNING and silently swallowing every logger.info() line.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    force=True,
)
logger = logging.getLogger("sf_backup")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class Config:
    # Salesforce / Connected App
    sf_consumer_key: str
    sf_username: str
    sf_login_url: str

    # Pardot
    pardot_client_id: str
    pardot_business_unit_id: str
    pardot_login_url: str

    # AWS
    s3_bucket: str
    kms_key_id: str
    aws_region: str
    secrets_manager_secret_id: str

    # Behaviour
    full_export_weekday: int  # 0 = Monday ... 6 = Sunday (Python convention)
    bulk_job_timeout_sec: int
    sns_topic_arn: Optional[str]
    volume_alert_threshold_pct: float
    bulk_api_quota_alert_pct: float

    # Email (SES)
    ses_sender_email: str  # must be verified in SES
    notification_emails: list  # comma-separated in env var

    # Lab: notifications go to a single fixed mailbox regardless of env vars
    LAB_EMAIL = "nhikhanh28@gmail.com"

    @staticmethod
    def from_env() -> "Config":
        emails = [Config.LAB_EMAIL]
        return Config(
            # Consumer key is a fallback only - production stores it in Secrets Manager
            # (key: sf_consumer_key). Env var kept for lab/backward compatibility.
            sf_consumer_key=os.environ.get("SF_CONSUMER_KEY", ""),
            sf_username=_require_env("SF_USERNAME"),
            sf_login_url=os.environ.get("SF_LOGIN_URL", "https://login.salesforce.com"),
            # Pardot is disabled by default ("skip"). To enable later: set both
            # env vars to real values and add pardot_* credentials to the secret.
            pardot_client_id=os.environ.get("PARDOT_CLIENT_ID", "skip"),
            pardot_business_unit_id=os.environ.get("PARDOT_BUSINESS_UNIT_ID", "skip"),
            pardot_login_url=os.environ.get(
                "PARDOT_LOGIN_URL", "https://login.salesforce.com"
            ),
            s3_bucket=_require_env("S3_BUCKET"),
            kms_key_id=_require_env("KMS_KEY_ID"),
            aws_region=os.environ.get("AWS_REGION_NAME")
            or os.environ.get("AWS_REGION", "us-west-2"),
            secrets_manager_secret_id=_require_env("SECRETS_MANAGER_SECRET_ID"),
            full_export_weekday=int(
                os.environ.get("FULL_EXPORT_WEEKDAY", "6")
            ),  # Sunday
            bulk_job_timeout_sec=int(os.environ.get("BULK_JOB_TIMEOUT_SEC", "1800")),
            sns_topic_arn=os.environ.get("SNS_TOPIC_ARN") or None,
            volume_alert_threshold_pct=float(
                os.environ.get("VOLUME_ALERT_THRESHOLD_PCT", "30")
            ),
            bulk_api_quota_alert_pct=float(
                os.environ.get("BULK_API_QUOTA_ALERT_PCT", "80")
            ),
            ses_sender_email=Config.LAB_EMAIL,
            notification_emails=emails,
        )


# --------------------------------------------------------------------------- #
# Secrets (AWS Secrets Manager)
# --------------------------------------------------------------------------- #


class SecretsStore:
    """Fetches and caches the JWT private key + Pardot credentials for one run.

    Expected secret (JSON) shape in Secrets Manager:
    {
      "sf_jwt_private_key": "-----BEGIN PRIVATE KEY-----...",
      "sf_consumer_key": "3MVG9...",          # preferred over SF_CONSUMER_KEY env var
      "pardot_client_secret": "...",
      "pardot_username": "...",
      "pardot_password": "...",
      "pardot_security_token": "..."          # empty string if IP is allowlisted
    }
    """

    def __init__(self, secret_id: str, region: str):
        self._client = boto3.client("secretsmanager", region_name=region)
        self._secret_id = secret_id
        self._cache: Optional[dict[str, str]] = None

    def get(self) -> dict[str, str]:
        if self._cache is None:
            resp = self._client.get_secret_value(SecretId=self._secret_id)
            self._cache = json.loads(resp["SecretString"])
        return self._cache


# --------------------------------------------------------------------------- #
# Retry helper
# --------------------------------------------------------------------------- #


def retry_with_backoff(
    fn, *, attempts: int = 4, base_delay: float = 2.0, retriable=(Exception,)
):
    """Run fn() with exponential backoff. Re-raises the last exception on failure."""
    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except retriable as exc:  # noqa: PERF203 - clarity over micro-perf here
            last_exc = exc
            if attempt == attempts:
                break
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "Attempt %s/%s failed (%s) - retrying in %.1fs",
                attempt,
                attempts,
                exc,
                delay,
            )
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Salesforce (Sales Cloud) - JWT Bearer auth + Bulk API export
# --------------------------------------------------------------------------- #

# Fallback static list, used only when EXPORT_SCOPE=list. The default scope is
# "all": every queryable object in the org is discovered via the Describe API,
# mirroring what Salesforce's native Weekly Export (WE_*.ZIP) produces.
OBJECTS_TO_EXPORT: dict[str, str] = {
    "Account": "SELECT Id, Name, Industry, BillingCountry, CreatedDate, LastModifiedDate FROM Account",
    "Contact": "SELECT Id, AccountId, Email, FirstName, LastName, CreatedDate, LastModifiedDate FROM Contact",
    "Lead": "SELECT Id, Email, Company, Status, CreatedDate, LastModifiedDate FROM Lead",
    "Opportunity": "SELECT Id, AccountId, Name, Amount, StageName, CloseDate, LastModifiedDate FROM Opportunity",
    "Task": "SELECT Id, WhoId, WhatId, Subject, Status, ActivityDate, LastModifiedDate FROM Task",
    "Campaign": "SELECT Id, Name, Status, StartDate, EndDate, LastModifiedDate FROM Campaign",
    "Product2": "SELECT Id, Name, ProductCode, IsActive, LastModifiedDate FROM Product2",
}

# Objects excluded from the daily run and processed only on the weekly full export
# (high volume / low restore value - see procedure section 5.4).
WEEKLY_ONLY_OBJECTS: set[str] = set()


def get_weekly_only_objects() -> set[str]:
    """Objects with very high volume and low restore value, excluded from the
    daily (incremental) export and processed on the weekly full export only
    (procedure section 5.4). Applies to BOTH Salesforce object names (e.g.
    "Task") and Pardot endpoints (e.g. "visitor-activities").

    Configured via env WEEKLY_ONLY_OBJECTS (comma-separated); the default
    covers the customer's stated example: Pardot Visitor / VisitorActivity.
    Merged with the static WEEKLY_ONLY_OBJECTS set above.
    """
    raw = os.environ.get("WEEKLY_ONLY_OBJECTS", "visitors,visitor-activities")
    from_env = {x.strip() for x in raw.split(",") if x.strip()}
    return WEEKLY_ONLY_OBJECTS | from_env


# Field types the Bulk/REST CSV export cannot represent. Compound fields
# (address/location) are decomposed into their component fields by Salesforce
# anyway, and base64 bodies (attachments) need a dedicated binary export flow.
UNSUPPORTED_FIELD_TYPES: set[str] = {"address", "location", "complexvalue", "base64"}

# Object name suffixes that are derived/system data with no restore value.
# Share/Feed/History/ChangeEvent tables regenerate from the parent records.
EXCLUDED_OBJECT_SUFFIXES: tuple[str, ...] = (
    "Share",
    "Feed",
    "History",
    "ChangeEvent",
    "EventRelation",
)


# Standard objects mirroring the customer scope, minus Quote: the Developer
# Edition lab org does not have the Quotes feature enabled.
CUSTOMER_STANDARD_OBJECTS: tuple[str, ...] = (
    "Account",
    "Contact",
    "Lead",
    "Opportunity",
    "Task",
    "Event",
    "Campaign",
    "Product2",
)


def _build_full_field_soql(sf: Salesforce, object_name: str) -> Optional[str]:
    """Describes one object and returns a SELECT of all exportable fields,
    or None if the object has no exportable fields."""
    field_desc = getattr(sf, object_name).describe()["fields"]
    fields = [f["name"] for f in field_desc if f["type"] not in UNSUPPORTED_FIELD_TYPES]
    return f"SELECT {', '.join(fields)} FROM {object_name}" if fields else None


def discover_export_objects(
    sf: Salesforce, scope: str, skip_empty: bool
) -> tuple[dict[str, str], int, int]:
    """Builds the {object_name: soql} map to export.

    scope="customer": the customer-agreed standard object list plus every
                      custom object (__c) discovered via the Describe API.
                      New custom objects are included automatically on the
                      next run - no code change needed.
    scope="all":      every queryable+replicateable object in the org
                      (equivalent to Salesforce's Weekly Export ZIP).
    scope="list":     the static OBJECTS_TO_EXPORT map (legacy).

    skip_empty: when True, runs a fast REST COUNT() per object and drops
    objects with zero records - saves Bulk API quota and wall-clock time.
    Returns (export_map, discovered_count, skipped_empty_count).
    """
    if scope == "list":
        return dict(OBJECTS_TO_EXPORT), len(OBJECTS_TO_EXPORT), 0

    if scope == "customer":
        # describe() is retried: transient Salesforce hiccups (maintenance
        # windows, instance failovers) surface as empty-body 404s here and
        # must not kill the whole run at the discovery step.
        described = retry_with_backoff(
            lambda: sf.describe()["sobjects"], attempts=3, base_delay=15
        )
        custom_objects = sorted(
            s["name"]
            for s in described
            if s["name"].endswith("__c")
            and s.get("queryable")
            and s.get("replicateable")
            and not s.get("deprecatedAndHidden")
        )
        candidates = list(CUSTOMER_STANDARD_OBJECTS) + custom_objects
        logger.info(
            "Customer scope: %s standard + %s custom objects (%s)",
            len(CUSTOMER_STANDARD_OBJECTS),
            len(custom_objects),
            ", ".join(custom_objects) or "none",
        )
        export_map: dict[str, str] = {}
        skipped = 0
        for object_name in candidates:
            try:
                if skip_empty:
                    if sf.query(f"SELECT COUNT() FROM {object_name}")["totalSize"] == 0:
                        skipped += 1
                        continue
                soql = _build_full_field_soql(sf, object_name)
                if soql:
                    export_map[object_name] = soql
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Skipping %s (describe/count failed): %s", object_name, exc
                )
                skipped += 1
        return export_map, len(candidates), skipped

    # scope == "all"
    described = retry_with_backoff(
        lambda: sf.describe()["sobjects"], attempts=3, base_delay=15
    )
    # replicateable is the flag Salesforce's own Weekly Export uses: it marks
    # real data objects and excludes system enums (CaseStatus, DataType, ...)
    # that the Bulk API rejects with INVALIDENTITY.
    candidates = [
        s["name"]
        for s in described
        if s.get("queryable")
        and s.get("replicateable")
        and not s.get("deprecatedAndHidden")
        and not any(s["name"].endswith(suffix) for suffix in EXCLUDED_OBJECT_SUFFIXES)
    ]
    logger.info("Describe API: %s queryable objects discovered", len(candidates))

    export_map: dict[str, str] = {}
    skipped_empty = 0
    for object_name in candidates:
        try:
            if skip_empty:
                count = sf.query(f"SELECT COUNT() FROM {object_name}")["totalSize"]
                if count == 0:
                    skipped_empty += 1
                    continue
            soql = _build_full_field_soql(sf, object_name)
            if not soql:
                continue
            export_map[object_name] = soql
        except Exception as exc:  # noqa: BLE001 - objects needing filters (e.g. *History views) raise here
            logger.debug(
                "Skipping %s (not exportable via generic query): %s", object_name, exc
            )
            skipped_empty += 1
    logger.info(
        "Export map built: %s objects with data, %s skipped",
        len(export_map),
        skipped_empty,
    )
    return export_map, len(candidates), skipped_empty


def resolve_consumer_key(cfg: Config, secrets: dict[str, str]) -> str:
    """Prefers sf_consumer_key from Secrets Manager; falls back to env var.

    Keeping the key out of Lambda env vars means it is not visible in the
    console, is audited via CloudTrail on every read, and rotates in one place.
    """
    key = secrets.get("sf_consumer_key", "").strip() or cfg.sf_consumer_key.strip()
    if not key:
        raise RuntimeError(
            "Salesforce consumer key not found: set sf_consumer_key in the "
            "Secrets Manager secret (preferred) or SF_CONSUMER_KEY env var."
        )
    return key


def get_salesforce_session(
    cfg: Config, private_key_pem: str, consumer_key: str
) -> Salesforce:
    payload = {
        "iss": consumer_key,
        "sub": cfg.sf_username,
        "aud": cfg.sf_login_url,
        "exp": int(time.time()) + 300,
    }
    assertion = jwt.encode(payload, private_key_pem, algorithm="RS256")

    def _do_auth():
        resp = requests.post(
            f"{cfg.sf_login_url}/services/oauth2/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    token_data = retry_with_backoff(_do_auth, attempts=3)
    return Salesforce(
        instance_url=token_data["instance_url"], session_id=token_data["access_token"]
    )


def export_object_rest(
    sf: Salesforce, object_name: str, soql_query: str, output_dir: str
) -> tuple[str, int]:
    """Fallback exporter using the REST API (query_all_iter) for objects that
    Bulk API 2.0 does not support (e.g. Quote). Streams records to CSV."""
    filepath = os.path.join(output_dir, f"{object_name}.csv")
    row_count = 0
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = None
        for record in sf.query_all_iter(soql_query):
            record.pop("attributes", None)
            if writer is None:
                writer = csv.DictWriter(f, fieldnames=list(record.keys()))
                writer.writeheader()
            writer.writerow(record)
            row_count += 1
    return filepath, row_count


# Timestamp fields usable for incremental filtering, in preference order.
# Some system objects (GroupMember, Period) lack LastModifiedDate but expose
# SystemModstamp; others (FiscalYearSettings) have neither and must always be
# exported in full - they are tiny settings tables, so the cost is negligible.
INCREMENTAL_TIMESTAMP_FIELDS: tuple[str, ...] = ("LastModifiedDate", "SystemModstamp")


def build_soql(base_query: str, incremental: bool) -> str:
    if not incremental:
        return base_query
    # The SELECT clause is generated from the object's Describe result, so a
    # field appearing there is authoritative proof the field exists.
    select_clause = base_query.split(" FROM ")[0]
    ts_field = next(
        (
            f
            for f in INCREMENTAL_TIMESTAMP_FIELDS
            if re.search(rf"(^|[,\s]){f}([,\s]|$)", select_clause)
        ),
        None,
    )
    if ts_field is None:
        return base_query  # no timestamp field on this object -> full export
    separator = " WHERE " if " WHERE " not in base_query.upper() else " AND "
    return f"{base_query}{separator}{ts_field} = LAST_N_DAYS:1"


def export_object_bulk(
    sf: Salesforce,
    object_name: str,
    soql_query: str,
    output_dir: str,
    wait_sec: int = 10,
) -> tuple[str, int]:
    """Runs a Bulk API 2.0 query job for one object, writes CSV to disk.

    simple-salesforce bulk2.query() is a Generator that yields CSV string chunks.
    Each chunk is a raw CSV string including header row (header repeated per chunk).
    wait_sec is the polling interval passed to bulk2 while waiting for the job.
    Returns (filepath, row_count).
    """
    filepath = os.path.join(output_dir, f"{object_name}.csv")
    row_count = 0

    bulk2_obj = getattr(sf.bulk2, object_name)

    # Generator must be consumed inside try/except for retry logic
    PERMANENT_BULK_ERRORS = (
        "INVALIDENTITY",
        "is not supported",
        "EXCEEDED_ID_LIMIT",
        "queryMore",
    )

    class _PermanentBulkError(Exception):
        """Non-retriable bulk failure - triggers immediate REST fallback."""

    def _fetch_all_chunks():
        chunks = []
        try:
            for csv_chunk in bulk2_obj.query(
                soql_query, max_records=50000, wait=wait_sec
            ):
                if csv_chunk:
                    chunks.append(csv_chunk)
        except (SalesforceError, SalesforceOperationError) as exc:
            if any(marker in str(exc) for marker in PERMANENT_BULK_ERRORS):
                raise _PermanentBulkError(str(exc)) from exc
            raise
        return chunks

    all_chunks = retry_with_backoff(
        _fetch_all_chunks,
        attempts=2,
        retriable=(
            SalesforceError,
            SalesforceOperationError,
            requests.exceptions.RequestException,
        ),
    )

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        header_written = False
        fieldnames = None
        for csv_chunk in all_chunks:
            # csv_chunk is raw CSV string, header included in every chunk
            lines = csv_chunk.strip().splitlines()
            if not lines:
                continue

            if not header_written:
                # First chunk: write header + data rows
                reader = csv.DictReader(lines)
                rows = list(reader)
                fieldnames = reader.fieldnames
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
                row_count += len(rows)
                header_written = True
            else:
                # Subsequent chunks: skip header line, write data rows only
                reader = csv.DictReader(lines, fieldnames=fieldnames)
                next(reader)  # skip repeated header
                rows = list(reader)
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writerows(rows)
                row_count += len(rows)

    return filepath, row_count


# --------------------------------------------------------------------------- #
# Pardot (Account Engagement) - API v5
# --------------------------------------------------------------------------- #


def get_pardot_token(cfg: Config, secrets: dict[str, str]) -> str:
    def _do_auth():
        resp = requests.post(
            f"{cfg.pardot_login_url}/services/oauth2/token",
            data={
                "grant_type": "password",
                "client_id": cfg.pardot_client_id,
                "client_secret": secrets["pardot_client_secret"],
                "username": secrets["pardot_username"],
                "password": secrets["pardot_password"]
                + secrets.get("pardot_security_token", ""),
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    return retry_with_backoff(_do_auth, attempts=3)


PARDOT_API_BASE = "https://pi.pardot.com/api/v5/objects"

# Pardot API v5 REQUIRES an explicit `fields` parameter on every read (unlike
# v4) and paginates with cursor tokens (nextPageUrl), not offsets. Field sets
# below are curated from the v5 object reference; if the customer org rejects
# a field (400 invalid field), the exporter automatically retries that object
# with PARDOT_MINIMAL_FIELDS so the backup still captures record identity.
#
# Default scope = the customer's agreed Pardot object list:
#   Prospect, List, ListMembership, EmailTemplate, ListEmail.
# Visitor / VisitorActivity are HIGH VOLUME (web behavioural history) and per
# the scope document are "to be evaluated according to actual retention
# needs" - enable them with env PARDOT_INCLUDE_HIGH_VOLUME=true once the
# customer confirms retention requirements and expected volume.
PARDOT_EXPORT_OBJECTS: dict[str, str] = {
    "prospects": (
        "id,email,firstName,lastName,company,jobTitle,country,score,grade,"
        "source,campaignId,createdAt,updatedAt,lastActivityAt,optedOut,doNotEmail"
    ),
    "lists": "id,name,isPublic,isDynamic,description,folderId,createdAt,updatedAt",
    "list-memberships": "id,listId,prospectId,optedOut,createdAt,updatedAt",
    "email-templates": "id,name,subject,type,isOneToOneEmail,isAutoresponderEmail,isDripEmail,isListEmail",
    "list-emails": "id,name,subject,campaignId,createdAt",
}

PARDOT_HIGH_VOLUME_OBJECTS: dict[str, str] = {
    "visitors": "id,pageViewCount,ipAddress,hostname,createdAt,updatedAt,prospectId",
    "visitor-activities": "id,prospectId,visitorId,type,typeName,details,campaignId,createdAt",
}

PARDOT_MINIMAL_FIELDS = "id,createdAt"


def export_pardot_object(
    token: str,
    business_unit_id: str,
    endpoint: str,
    fields: str,
    output_dir: str,
) -> tuple[str, int]:
    """Exports one Pardot v5 object to CSV using cursor-based pagination.

    Follows nextPageUrl until exhausted (limit=1000 per page - the v5 max for
    most objects). Handles 429 rate limits with Retry-After, and falls back to
    PARDOT_MINIMAL_FIELDS once if the org rejects a curated field.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Pardot-Business-Unit-Id": business_unit_id,
    }
    label = "pardot_" + endpoint.replace("-", "_")

    class _PardotHTTPError(Exception):
        """Permanent (non-429) HTTP error - deliberately NOT a RequestException
        subclass so retry_with_backoff does not waste 5 attempts on a 400."""

        def __init__(self, response):
            self.response = response
            super().__init__(
                f"HTTP {response.status_code} from Pardot: {response.text[:300]}"
            )

    def _fetch_all(fields_to_use: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        url: Optional[str] = f"{PARDOT_API_BASE}/{endpoint}"
        params: Optional[dict[str, Any]] = {"fields": fields_to_use, "limit": 1000}
        while url:

            def _fetch_page(url=url, params=params):
                resp = requests.get(url, headers=headers, params=params, timeout=60)
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", 30))
                    logger.warning(
                        "Pardot rate limited on %s - sleeping %ss", endpoint, wait
                    )
                    time.sleep(wait)
                    raise requests.exceptions.RequestException("rate limited - retry")
                if resp.status_code >= 400:
                    raise _PardotHTTPError(resp)  # permanent - fail fast, no retry
                return resp.json()

            page = retry_with_backoff(
                _fetch_page,
                attempts=5,
                retriable=(requests.exceptions.RequestException,),
            )
            records.extend(page.get("values", []))
            next_url = page.get("nextPageUrl")
            if next_url and next_url.startswith("/"):
                next_url = "https://pi.pardot.com" + next_url
            url = next_url
            params = None  # nextPageUrl already carries the query string

        return records

    try:
        records = _fetch_all(fields)
    except _PardotHTTPError as exc:
        body = getattr(exc.response, "text", "") or ""
        if exc.response.status_code == 400 and "field" in body.lower():
            logger.warning(
                "%s: org rejected curated fields (%s) - retrying with minimal fields. "
                "Adjust PARDOT_EXPORT_OBJECTS to match this org's schema.",
                label,
                body[:200],
            )
            records = _fetch_all(PARDOT_MINIMAL_FIELDS)
        else:
            raise

    filepath = os.path.join(output_dir, f"{label}.csv")
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        if records:
            fieldnames = sorted({k for row in records for k in row.keys()})
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in records:
                # nested structures (e.g. expanded relations) -> JSON strings
                writer.writerow(
                    {
                        k: json.dumps(v, ensure_ascii=False)
                        if isinstance(v, (dict, list))
                        else v
                        for k, v in row.items()
                    }
                )
        else:
            f.write("")
    return filepath, len(records)


# --------------------------------------------------------------------------- #
# S3 upload
# --------------------------------------------------------------------------- #


def upload_to_s3(
    s3_client,
    filepath: str,
    object_name: str,
    bucket_name: str,
    kms_key_id: str,
    date_str: str,
) -> tuple[str, int]:
    gz_path = f"{filepath}.gz"
    with open(filepath, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)

    file_size = os.path.getsize(gz_path)
    s3_key = f"salesforce-backup/{object_name}/{date_str}/{object_name}.csv.gz"

    def _do_upload():
        # SoD / encrypt-only compliance: the backup role has s3:PutObject but
        # NOT s3:GetObject, so the old head_object read-back integrity check is
        # impossible. ChecksumAlgorithm=SHA256 is the stronger replacement:
        # S3 recomputes the checksum server-side on receipt and REJECTS the
        # upload if any byte was corrupted in transit - no read-back needed.
        s3_client.upload_file(
            gz_path,
            bucket_name,
            s3_key,
            ExtraArgs={
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": kms_key_id,
                "ChecksumAlgorithm": "SHA256",
            },
        )

    retry_with_backoff(_do_upload, attempts=3, retriable=(ClientError,))
    if file_size <= 0:
        raise RuntimeError(f"Refusing to treat empty archive as success: {s3_key}")

    # cleanup local temp files - important on long-lived EC2/ECS execution
    for path in (filepath, gz_path):
        try:
            os.remove(path)
        except OSError:
            pass

    return s3_key, file_size


# --------------------------------------------------------------------------- #
# Logging / alerting
# --------------------------------------------------------------------------- #


@dataclass
class ObjectResult:
    object_name: str
    status: str  # "success" | "failed"
    row_count: int = 0
    s3_key: Optional[str] = None
    file_size_bytes: int = 0
    error: Optional[str] = None


@dataclass
class RunReport:
    run_id: str
    started_at: str
    mode: str  # "full" | "incremental"
    results: list[ObjectResult] = field(default_factory=list)
    finished_at: Optional[str] = None
    duration_sec: Optional[float] = None
    bulk_api_jobs_consumed: int = 0
    warnings: list = field(default_factory=list)  # anomaly / quota warnings
    bulk_quota: Optional[dict] = None  # {"used": n, "max": n, "pct": f}

    @property
    def total_rows(self) -> int:
        return sum(r.row_count for r in self.results if r.status == "success")

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": self.duration_sec,
            "mode": self.mode,
            "bulk_api_jobs_consumed": self.bulk_api_jobs_consumed,
            "total_rows": self.total_rows,
            "warnings": self.warnings,
            "bulk_quota": self.bulk_quota,
            "objects": [r.__dict__ for r in self.results],
            "overall_status": "success"
            if all(r.status == "success" for r in self.results)
            else "partial_or_failed",
        }


def write_log_to_s3(
    s3_client, bucket: str, report: RunReport, date_str: str, kms_key_id: str
) -> None:
    log_key = f"logs/{date_str}/execution_log_{report.run_id}.json"
    s3_client.put_object(
        Bucket=bucket,
        Key=log_key,
        Body=json.dumps(report.to_json(), indent=2).encode("utf-8"),
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=kms_key_id,
        ChecksumAlgorithm="SHA256",
    )
    logger.info("Execution log written to s3://%s/%s", bucket, log_key)


def send_alert(
    sns_client, topic_arn: Optional[str], subject: str, message: str
) -> None:
    """Mid-run per-object failure alert via SNS (plain text, fast)."""
    logger.warning("ALERT: %s - %s", subject, message)
    if not topic_arn or sns_client is None:
        return
    try:
        sns_client.publish(TopicArn=topic_arn, Subject=subject[:100], Message=message)
    except ClientError as exc:
        logger.error("Failed to publish SNS alert: %s", exc)


# --------------------------------------------------------------------------- #
# Email report (SES) - full HTML summary sent at end of every run
# --------------------------------------------------------------------------- #


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def build_email_html(report: RunReport, s3_bucket: str) -> tuple[str, str]:
    """Returns (subject, html_body) for the final backup summary email."""

    failed = [r for r in report.results if r.status == "failed"]
    success = [r for r in report.results if r.status == "success"]
    overall = (
        "✅ SUCCESS" if not failed else ("❌ FAILED" if not success else "⚠️ PARTIAL")
    )
    status_color = (
        "#2e7d32" if not failed else ("#c62828" if not success else "#e65100")
    )

    subject = f"[Salesforce Backup] {overall} – {report.started_at[:10]} ({report.mode.upper()})"

    # Object rows
    rows_html = ""
    for r in report.results:
        icon = "✅" if r.status == "success" else "❌"
        size = _fmt_bytes(r.file_size_bytes) if r.file_size_bytes else "—"
        rows_html += f"""
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #e0e0e0;">{icon} {r.object_name}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e0e0e0;text-align:right;">{r.row_count:,}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e0e0e0;text-align:right;">{size}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e0e0e0;font-size:12px;color:#555;">{r.error or r.s3_key or "—"}</td>
        </tr>"""

    # Error detail block (only when failures present)
    warnings_section = ""
    if report.warnings:
        warning_items = "".join(f"<li>{w}</li>" for w in report.warnings)
        warnings_section = f"""
        <div style="margin-top:24px;padding:16px;background:#fff8e1;border-left:4px solid #f57f17;border-radius:4px;">
          <b style="color:#e65100;">Warnings (backup completed, attention needed):</b>
          <ul style="margin:8px 0 0 0;padding-left:20px;color:#333;">{warning_items}</ul>
        </div>"""

    error_section = ""
    if failed:
        error_items = "".join(
            f"<li><b>{r.object_name}</b>: {r.error}</li>" for r in failed
        )
        error_section = f"""
        <div style="margin-top:24px;padding:16px;background:#ffebee;border-left:4px solid #c62828;border-radius:4px;">
          <b style="color:#c62828;">Errors requiring attention:</b>
          <ul style="margin:8px 0 0 0;padding-left:20px;color:#333;">{error_items}</ul>
        </div>"""

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;color:#212121;background:#f5f5f5;margin:0;padding:24px;">
  <div style="max-width:780px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">

    <!-- Header -->
    <div style="background:{status_color};padding:24px 32px;">
      <h1 style="margin:0;font-size:22px;color:#fff;">Salesforce → S3 Backup Report</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,.85);font-size:14px;">{overall}</p>
    </div>

    <!-- Summary bar -->
    <div style="display:flex;gap:0;border-bottom:1px solid #e0e0e0;">
      <div style="flex:1;padding:16px 24px;border-right:1px solid #e0e0e0;">
        <div style="font-size:11px;color:#777;text-transform:uppercase;letter-spacing:.5px;">Date</div>
        <div style="font-size:15px;font-weight:600;">{report.started_at[:10]}</div>
      </div>
      <div style="flex:1;padding:16px 24px;border-right:1px solid #e0e0e0;">
        <div style="font-size:11px;color:#777;text-transform:uppercase;letter-spacing:.5px;">Mode</div>
        <div style="font-size:15px;font-weight:600;">{report.mode.capitalize()}</div>
      </div>
      <div style="flex:1;padding:16px 24px;border-right:1px solid #e0e0e0;">
        <div style="font-size:11px;color:#777;text-transform:uppercase;letter-spacing:.5px;">Duration</div>
        <div style="font-size:15px;font-weight:600;">{int(report.duration_sec or 0)}s</div>
      </div>
      <div style="flex:1;padding:16px 24px;border-right:1px solid #e0e0e0;">
        <div style="font-size:11px;color:#777;text-transform:uppercase;letter-spacing:.5px;">Objects OK</div>
        <div style="font-size:15px;font-weight:600;color:#2e7d32;">{len(success)}/{len(report.results)}</div>
      </div>
      <div style="flex:1;padding:16px 24px;">
        <div style="font-size:11px;color:#777;text-transform:uppercase;letter-spacing:.5px;">Bulk API Jobs</div>
        <div style="font-size:15px;font-weight:600;">{report.bulk_api_jobs_consumed}</div>
      </div>
    </div>

    <!-- Object table -->
    <div style="padding:24px 32px;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead>
          <tr style="background:#f5f5f5;">
            <th style="padding:10px 12px;text-align:left;font-size:12px;color:#555;font-weight:600;border-bottom:2px solid #e0e0e0;">Object</th>
            <th style="padding:10px 12px;text-align:right;font-size:12px;color:#555;font-weight:600;border-bottom:2px solid #e0e0e0;">Rows</th>
            <th style="padding:10px 12px;text-align:right;font-size:12px;color:#555;font-weight:600;border-bottom:2px solid #e0e0e0;">Size (gz)</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;color:#555;font-weight:600;border-bottom:2px solid #e0e0e0;">S3 Key / Error</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>

      {error_section}

      {warnings_section}

      <!-- Footer info -->
      <div style="margin-top:24px;padding:14px 16px;background:#f5f5f5;border-radius:4px;font-size:12px;color:#666;">
        <b>Bucket:</b> {s3_bucket} &nbsp;|&nbsp;
        <b>Run ID:</b> {report.run_id} &nbsp;|&nbsp;
        <b>Started:</b> {report.started_at} &nbsp;|&nbsp;
        <b>Finished:</b> {report.finished_at}
      </div>
    </div>

    <!-- Footer -->
    <div style="padding:16px 32px;background:#fafafa;border-top:1px solid #e0e0e0;font-size:11px;color:#999;">
      This is an automated notification from the Salesforce Backup system (TEAMWORK SYSTEM INFRASTRUCTURE).
      Do not reply to this email.
    </div>
  </div>
</body>
</html>"""

    return subject, html


def send_email_report(ses_client, cfg: "Config", report: RunReport) -> None:
    """Sends the full HTML backup summary via Amazon SES."""
    if not cfg.notification_emails:
        logger.info("NOTIFICATION_EMAILS not set - skipping SES email report")
        return

    subject, html_body = build_email_html(report, cfg.s3_bucket)

    # Plain-text fallback for email clients that don't render HTML
    failed = [r for r in report.results if r.status == "failed"]
    success = [r for r in report.results if r.status == "success"]
    text_lines = [
        f"Salesforce Backup Report - {report.started_at[:10]}",
        f"Overall: {'SUCCESS' if not failed else 'PARTIAL/FAILED'}",
        f"Mode: {report.mode}  |  Duration: {int(report.duration_sec or 0)}s",
        f"Objects OK: {len(success)}/{len(report.results)}",
        "",
        "Details:",
    ]
    for r in report.results:
        status_txt = "OK" if r.status == "success" else "FAILED"
        text_lines.append(
            f"  [{status_txt}] {r.object_name} - {r.row_count:,} rows  {r.error or ''}"
        )
    text_body = "\n".join(text_lines)

    try:
        ses_client.send_email(
            Source=cfg.ses_sender_email,
            Destination={"ToAddresses": cfg.notification_emails},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": text_body, "Charset": "UTF-8"},
                    "Html": {"Data": html_body, "Charset": "UTF-8"},
                },
            },
        )
        logger.info("Email report sent to %s", cfg.notification_emails)
    except ClientError as exc:
        logger.error("Failed to send SES email report: %s", exc)


CLOUDWATCH_NAMESPACE = "SalesforceBackup"


def publish_volume_metric(cw_client, report: "RunReport") -> None:
    """Publishes this run's total row count as a CloudWatch custom metric.
    CloudWatch is the SoD-compliant history store: the encrypt-only backup
    role cannot read objects back from S3, and the metric carries only a
    count - no PII ever leaves the encrypted bucket."""
    try:
        cw_client.put_metric_data(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricData=[
                {
                    "MetricName": "TotalRows",
                    "Dimensions": [{"Name": "Mode", "Value": report.mode}],
                    "Value": float(report.total_rows),
                    "Unit": "Count",
                }
            ],
        )
    except Exception as exc:  # noqa: BLE001 - best-effort
        logger.warning("Volume metric publish skipped: %s", exc)


def check_volume_anomaly(
    cw_client, report: "RunReport", threshold_pct: float
) -> Optional[str]:
    """Compares this run's total exported rows to the average of same-mode runs
    over the previous 7 days, read from CloudWatch custom metrics (the
    encrypt-only role cannot read execution logs back from S3 - see
    publish_volume_metric for the SoD rationale).

    Same-mode comparison is essential: incremental runs export deltas while
    full runs export everything. Requires at least 3 historical same-mode
    datapoints before alerting. Best-effort: errors are logged and ignored.
    """
    try:
        now = datetime.now(timezone.utc)
        resp = cw_client.get_metric_statistics(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricName="TotalRows",
            Dimensions=[{"Name": "Mode", "Value": report.mode}],
            StartTime=now - timedelta(days=7),
            EndTime=now - timedelta(minutes=5),  # exclude this run if already published
            Period=86400,
            Statistics=["Average", "SampleCount"],
        )
        datapoints = resp.get("Datapoints", [])
        samples = int(sum(d.get("SampleCount", 0) for d in datapoints))
        if samples < 3:
            logger.info(
                "Volume anomaly check: only %s historical %s datapoint(s) in last 7 days - need 3, skipping",
                samples,
                report.mode,
            )
            return None
        # weight daily averages by their sample counts for a true 7-day mean
        weighted = sum(d["Average"] * d["SampleCount"] for d in datapoints)
        avg = weighted / samples
        current = report.total_rows
        if avg <= 0:
            return None
        deviation_pct = (current - avg) / avg * 100
        logger.info(
            "Volume anomaly check (%s mode): current=%s rows, 7-day avg=%.0f (%s samples), deviation=%+.1f%%",
            report.mode,
            current,
            avg,
            samples,
            deviation_pct,
        )
        if abs(deviation_pct) > threshold_pct:
            return (
                f"Exported volume anomaly: {current:,} rows this run vs 7-day "
                f"{report.mode} average of {avg:,.0f} rows ({deviation_pct:+.1f}%, "
                f"threshold ±{threshold_pct:.0f}%). Possible missing data or "
                f"source-side anomaly - verify before trusting this backup."
            )
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Volume anomaly check skipped due to error: %s", exc)
        return None


def check_bulk_api_quota(
    sf: "Salesforce", report: "RunReport", threshold_pct: float
) -> Optional[str]:
    """Reads org-wide Bulk API v2 query-job usage from the REST /limits endpoint
    and warns when consumption crosses threshold_pct of the daily quota.

    Uses org-level numbers (not just this run's jobs) because other
    integrations share the same rolling 24-hour quota.
    Best-effort: any error is logged and ignored (non-fatal).
    """
    try:
        limits = sf.limits()
        # Bulk API 2.0 query jobs is the quota this script consumes; fall back
        # to the classic Bulk API counter if the key is absent on the org.
        for key in (
            "DailyBulkV2QueryJobs",
            "DailyBulkApiBatches",
            "DailyBulkApiRequests",
        ):
            if key in limits:
                quota = limits[key]
                break
        else:
            logger.info(
                "Bulk API quota check: no bulk quota key found in /limits - skipping"
            )
            return None
        max_q = quota.get("Max", 0)
        remaining = quota.get("Remaining", 0)
        used = max_q - remaining
        pct = (used / max_q * 100) if max_q else 0.0
        report.bulk_quota = {
            "key": key,
            "used": used,
            "max": max_q,
            "pct": round(pct, 1),
        }
        logger.info("Bulk API quota (%s): %s/%s used (%.1f%%)", key, used, max_q, pct)
        if pct >= threshold_pct:
            return (
                f"Bulk API quota warning: {used:,}/{max_q:,} daily {key} consumed "
                f"({pct:.1f}%, threshold {threshold_pct:.0f}%). Backups may start "
                f"failing when the quota is exhausted - investigate which "
                f"integrations are consuming it."
            )
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Bulk API quota check skipped due to error: %s", exc)
        return None


# --------------------------------------------------------------------------- #
# Main orchestration
# --------------------------------------------------------------------------- #


def run_backup(
    cfg: Optional[Config] = None, mode_override: Optional[str] = None
) -> dict[str, Any]:
    """mode_override: "full" or "incremental" forces the mode regardless of
    weekday - e.g. invoke Lambda with payload {"mode": "full"} for an on-demand
    full export. Default (None) keeps the weekday-based schedule."""
    cfg = cfg or Config.from_env()
    started = datetime.now(timezone.utc)
    if mode_override in ("full", "incremental"):
        run_mode = mode_override
    else:
        run_mode = (
            "full" if started.weekday() == cfg.full_export_weekday else "incremental"
        )
    report = RunReport(
        run_id=str(uuid.uuid4()),
        started_at=started.isoformat(),
        mode=run_mode,
    )
    date_str = started.strftime("%Y/%m/%d")

    s3_client = boto3.client("s3", region_name=cfg.aws_region)
    sns_client = (
        boto3.client("sns", region_name=cfg.aws_region) if cfg.sns_topic_arn else None
    )
    ses_client = boto3.client("ses", region_name=cfg.aws_region)
    secrets_store = SecretsStore(cfg.secrets_manager_secret_id, cfg.aws_region)

    incremental = report.mode == "incremental"
    logger.info(
        "Starting Salesforce/Pardot backup run %s (mode=%s)", report.run_id, report.mode
    )

    with tempfile.TemporaryDirectory(prefix="sf_backup_") as tmp_dir:
        # ---- Sales Cloud (Bulk API) ----
        try:
            secrets = secrets_store.get()
            consumer_key = resolve_consumer_key(cfg, secrets)
            sf = get_salesforce_session(
                cfg, secrets["sf_jwt_private_key"], consumer_key
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Salesforce authentication failed")
            send_alert(
                sns_client,
                cfg.sns_topic_arn,
                "SF Backup: Salesforce auth FAILED",
                str(exc),
            )
            report.results.append(
                ObjectResult(
                    object_name="__auth_sales_cloud__", status="failed", error=str(exc)
                )
            )
            sf = None

        if sf is not None:
            export_scope = os.environ.get("EXPORT_SCOPE", "customer").strip().lower()
            skip_empty = (
                os.environ.get("SKIP_EMPTY_OBJECTS", "true").strip().lower() != "false"
            )
            try:
                export_map, discovered, skipped = discover_export_objects(
                    sf, export_scope, skip_empty
                )
            except Exception:  # noqa: BLE001 - discovery failure falls back to static list
                logger.exception(
                    "Object discovery failed - falling back to static list"
                )
                export_map, discovered, skipped = (
                    dict(OBJECTS_TO_EXPORT),
                    len(OBJECTS_TO_EXPORT),
                    0,
                )
            logger.info(
                "Exporting %s objects (scope=%s, discovered=%s, skipped=%s, mode=%s)",
                len(export_map),
                export_scope,
                discovered,
                skipped,
                report.mode,
            )

            def _export_one(object_name: str, base_query: str) -> ObjectResult:
                """Full lifecycle for one object: export (bulk or REST fallback)
                then upload to S3. Runs inside a worker thread; must never raise -
                every outcome is returned as an ObjectResult."""
                soql = build_soql(base_query, incremental)
                try:
                    used_bulk = True
                    try:
                        filepath, row_count = export_object_bulk(
                            sf, object_name, soql, tmp_dir
                        )
                    except Exception as bulk_exc:  # noqa: BLE001
                        # Permanent Bulk 2.0 rejections (unsupported entity, no
                        # queryMore support, ...) fall back to the REST API.
                        markers = (
                            "INVALIDENTITY",
                            "is not supported",
                            "EXCEEDED_ID_LIMIT",
                            "queryMore",
                            "_PermanentBulkError",
                        )
                        if any(
                            m in str(bulk_exc) or m in type(bulk_exc).__name__
                            for m in markers
                        ):
                            logger.info(
                                "%s not exportable via Bulk 2.0 - using REST fallback",
                                object_name,
                            )
                            used_bulk = False
                            filepath, row_count = export_object_rest(
                                sf, object_name, soql, tmp_dir
                            )
                        else:
                            raise
                    s3_key, size = upload_to_s3(
                        s3_client,
                        filepath,
                        object_name,
                        cfg.s3_bucket,
                        cfg.kms_key_id,
                        date_str,
                    )
                    logger.info(
                        "Exported %s: %s rows -> s3://%s/%s",
                        object_name,
                        row_count,
                        cfg.s3_bucket,
                        s3_key,
                    )
                    result = ObjectResult(
                        object_name=object_name,
                        status="success",
                        row_count=row_count,
                        s3_key=s3_key,
                        file_size_bytes=size,
                    )
                    result._used_bulk = used_bulk  # type: ignore[attr-defined]
                    return result
                except Exception as exc:  # noqa: BLE001 - one object must never kill the whole run
                    logger.exception("Export failed for object %s", object_name)
                    send_alert(
                        sns_client,
                        cfg.sns_topic_arn,
                        f"SF Backup: {object_name} export FAILED",
                        str(exc),
                    )
                    return ObjectResult(
                        object_name=object_name, status="failed", error=str(exc)
                    )

            # Parallel dispatch: Bulk API jobs run server-side on Salesforce, so
            # submitting them concurrently collapses the ~15s per-object job
            # overhead from (N x 15s) sequential to roughly one job cycle total.
            # MAX_PARALLEL_EXPORTS caps concurrent jobs to stay polite with the
            # org's Bulk API queue (Salesforce processes ~5-10 jobs in parallel).
            max_workers = int(os.environ.get("MAX_PARALLEL_EXPORTS", "6"))
            weekly_only = get_weekly_only_objects()
            deferred = [
                name for name in export_map if incremental and name in weekly_only
            ]
            if deferred:
                logger.info(
                    "Deferred to weekly full export (high volume / low restore value): %s",
                    ", ".join(deferred),
                )
            to_export = [
                (name, q)
                for name, q in export_map.items()
                if not (incremental and name in weekly_only)
            ]
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(_export_one, name, q): name for name, q in to_export
                }
                for future in as_completed(futures):
                    result = (
                        future.result()
                    )  # never raises - worker returns ObjectResult
                    report.results.append(result)
                    if result.status == "success" and getattr(
                        result, "_used_bulk", False
                    ):
                        report.bulk_api_jobs_consumed += 1

        # ---- Pardot (Account Engagement) ----
        # PARDOT_CLIENT_ID=skip disables the export for orgs without a Pardot
        # license (e.g. Developer Edition labs). For customer production orgs
        # (Enterprise+) this must be a real client id - validated below.
        if cfg.pardot_client_id.strip().lower() == "skip":
            logger.info("Pardot export skipped (PARDOT_CLIENT_ID=skip)")
        else:
            try:
                secrets = secrets_store.get()
                missing = [
                    k
                    for k in (
                        "pardot_client_secret",
                        "pardot_username",
                        "pardot_password",
                    )
                    if not secrets.get(k, "").strip()
                    or secrets.get(k, "").strip().lower() == "skip"
                ]
                if missing:
                    raise RuntimeError(
                        f"Pardot enabled (PARDOT_CLIENT_ID set) but Secrets Manager is "
                        f"missing real values for: {', '.join(missing)}"
                    )
                if (
                    not cfg.pardot_business_unit_id.strip()
                    or cfg.pardot_business_unit_id.strip().lower() == "skip"
                ):
                    raise RuntimeError(
                        "Pardot enabled but PARDOT_BUSINESS_UNIT_ID is not set to a real "
                        "Business Unit Id (0Uv...). Get it from Setup > Account Engagement."
                    )
                token = get_pardot_token(cfg, secrets)

                pardot_objects = dict(PARDOT_EXPORT_OBJECTS)
                if (
                    os.environ.get("PARDOT_INCLUDE_HIGH_VOLUME", "false")
                    .strip()
                    .lower()
                    == "true"
                ):
                    pardot_objects.update(PARDOT_HIGH_VOLUME_OBJECTS)

                # Weekly-only deferral applies to Pardot endpoints too: on the
                # daily incremental run, high-volume endpoints (default:
                # visitors, visitor-activities) are skipped and exported only
                # on the weekly full run.
                weekly_only = get_weekly_only_objects()
                if incremental:
                    deferred_pd = [
                        ep
                        for ep in pardot_objects
                        if ep in weekly_only
                        or f"pardot_{ep.replace('-', '_')}" in weekly_only
                    ]
                    for ep in deferred_pd:
                        pardot_objects.pop(ep)
                    if deferred_pd:
                        logger.info(
                            "Pardot endpoints deferred to weekly full export: %s",
                            ", ".join(deferred_pd),
                        )
                logger.info(
                    "Pardot export scope: %s",
                    ", ".join(pardot_objects) or "(none this run)",
                )

                for endpoint, fields in pardot_objects.items():
                    label = "pardot_" + endpoint.replace("-", "_")
                    try:
                        filepath, row_count = export_pardot_object(
                            token,
                            cfg.pardot_business_unit_id,
                            endpoint,
                            fields,
                            tmp_dir,
                        )
                        s3_key, size = upload_to_s3(
                            s3_client,
                            filepath,
                            label,
                            cfg.s3_bucket,
                            cfg.kms_key_id,
                            date_str,
                        )
                        report.results.append(
                            ObjectResult(
                                object_name=label,
                                status="success",
                                row_count=row_count,
                                s3_key=s3_key,
                                file_size_bytes=size,
                            )
                        )
                        logger.info(
                            "Exported %s: %s rows -> s3://%s/%s",
                            label,
                            row_count,
                            cfg.s3_bucket,
                            s3_key,
                        )
                    except Exception as exc:  # noqa: BLE001 - one Pardot object must not kill the rest
                        logger.exception("Pardot export failed for %s", label)
                        report.results.append(
                            ObjectResult(
                                object_name=label, status="failed", error=str(exc)
                            )
                        )
                        send_alert(
                            sns_client,
                            cfg.sns_topic_arn,
                            f"SF Backup: {label} export FAILED",
                            str(exc),
                        )
            except Exception as exc:  # noqa: BLE001 - auth / validation failure for Pardot as a whole
                logger.exception("Pardot export failed")
                report.results.append(
                    ObjectResult(
                        object_name="pardot_auth", status="failed", error=str(exc)
                    )
                )
                send_alert(
                    sns_client,
                    cfg.sns_topic_arn,
                    "SF Backup: Pardot export FAILED",
                    str(exc),
                )

    finished = datetime.now(timezone.utc)
    report.finished_at = finished.isoformat()
    report.duration_sec = (finished - started).total_seconds()

    # ---- Post-run health checks (procedure sections 7.2 / 7.3) ----
    cw_client = boto3.client("cloudwatch", region_name=cfg.aws_region)
    volume_warning = check_volume_anomaly(
        cw_client, report, cfg.volume_alert_threshold_pct
    )
    if volume_warning:
        report.warnings.append(volume_warning)
        send_alert(
            sns_client,
            cfg.sns_topic_arn,
            "SF Backup: VOLUME ANOMALY detected",
            volume_warning,
        )
    publish_volume_metric(
        cw_client, report
    )  # after the check so today's value is not in its own baseline
    if sf is not None:
        quota_warning = check_bulk_api_quota(sf, report, cfg.bulk_api_quota_alert_pct)
        if quota_warning:
            report.warnings.append(quota_warning)
            send_alert(
                sns_client,
                cfg.sns_topic_arn,
                "SF Backup: Bulk API quota warning",
                quota_warning,
            )

    write_log_to_s3(s3_client, cfg.s3_bucket, report, date_str, cfg.kms_key_id)

    failed = [r for r in report.results if r.status == "failed"]

    # SNS: mid-run per-object failures already sent above; send one final summary if any
    if failed:
        send_alert(
            sns_client,
            cfg.sns_topic_arn,
            f"SF Backup: run {report.run_id} completed with {len(failed)} failure(s)",
            json.dumps([r.__dict__ for r in failed], indent=2),
        )

    # SES: send full HTML email report to notification_emails regardless of outcome
    send_email_report(ses_client, cfg, report)

    logger.info(
        "Backup run %s finished in %.1fs - %s/%s objects OK",
        report.run_id,
        report.duration_sec,
        len(report.results) - len(failed),
        len(report.results),
    )
    return report.to_json()


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def lambda_handler(event, context):  # noqa: ANN001, ARG001 - AWS Lambda signature
    mode_override = (event or {}).get("mode") if isinstance(event, dict) else None
    result = run_backup(mode_override=mode_override)
    status_code = 200 if result["overall_status"] == "success" else 500
    return {"statusCode": status_code, "body": json.dumps(result)}


# --------------------------------------------------------------------------- #
# AWS Step Functions entry points
#
# Architecture: Discover -> Parallel[ Map(ExportObject, MaxConcurrency=6),
#               ExportPardot ] -> Aggregate.
# One Lambda function serves all four actions via step_handler; each Map
# iteration is its own invocation with its own 15-minute budget, removing the
# single-run ceiling of the monolithic lambda_handler.
#
# Payload discipline: Discover returns object NAMES only (not SOQL) to stay
# far below the 256KB Step Functions state-size limit; each worker rebuilds
# its own SOQL from the Describe API.
# --------------------------------------------------------------------------- #


def _sfn_auth(cfg: Config) -> Salesforce:
    secrets = SecretsStore(cfg.secrets_manager_secret_id, cfg.aws_region).get()
    consumer_key = resolve_consumer_key(cfg, secrets)
    return get_salesforce_session(cfg, secrets["sf_jwt_private_key"], consumer_key)


def _sfn_discover(event: dict) -> dict:
    """Step 1: authenticate, discover objects, decide run mode. Small output."""
    cfg = Config.from_env()
    started = datetime.now(timezone.utc)
    override = event.get("mode")
    if override in ("full", "incremental"):
        mode = override
    else:
        mode = "full" if started.weekday() == cfg.full_export_weekday else "incremental"
    incremental = mode == "incremental"

    sf = _sfn_auth(cfg)
    scope = os.environ.get("EXPORT_SCOPE", "customer").strip().lower()
    skip_empty = os.environ.get("SKIP_EMPTY_OBJECTS", "true").strip().lower() != "false"
    export_map, discovered, skipped = discover_export_objects(sf, scope, skip_empty)

    weekly_only = get_weekly_only_objects()
    objects = [n for n in export_map if not (incremental and n in weekly_only)]

    pardot_enabled = cfg.pardot_client_id.strip().lower() != "skip"
    pardot_endpoints: list = []
    if pardot_enabled:
        p = dict(PARDOT_EXPORT_OBJECTS)
        if (
            os.environ.get("PARDOT_INCLUDE_HIGH_VOLUME", "false").strip().lower()
            == "true"
        ):
            p.update(PARDOT_HIGH_VOLUME_OBJECTS)
        if incremental:
            p = {
                ep: f
                for ep, f in p.items()
                if ep not in weekly_only
                and f"pardot_{ep.replace('-', '_')}" not in weekly_only
            }
        pardot_endpoints = list(p)

    meta = {
        "run_id": str(uuid.uuid4()),
        "mode": mode,
        "started_at": started.isoformat(),
        "date_str": started.strftime("%Y/%m/%d"),
    }
    logger.info(
        "SFN discover: %s objects, pardot=%s (%s), mode=%s",
        len(objects),
        pardot_enabled,
        ",".join(pardot_endpoints) or "-",
        mode,
    )
    return {
        "meta": meta,
        "objects": objects,
        "pardot_enabled": pardot_enabled,
        "pardot_endpoints": pardot_endpoints,
    }


def _sfn_export_object(event: dict) -> dict:
    """Map iteration: export ONE object (bulk with REST fallback) and upload.
    Never raises - every outcome is a result dict so one object can never
    fail the whole state machine."""
    cfg = Config.from_env()
    meta = event["meta"]
    object_name = event["object_name"]
    incremental = meta["mode"] == "incremental"
    s3_client = boto3.client("s3", region_name=cfg.aws_region)
    try:
        sf = _sfn_auth(cfg)
        base_query = _build_full_field_soql(sf, object_name)
        if not base_query:
            return {
                "object_name": object_name,
                "status": "failed",
                "row_count": 0,
                "s3_key": None,
                "file_size_bytes": 0,
                "error": "no exportable fields",
                "used_bulk": False,
            }
        soql = build_soql(base_query, incremental)
        used_bulk = True
        with tempfile.TemporaryDirectory(prefix="sfn_") as tmp_dir:
            try:
                filepath, row_count = export_object_bulk(sf, object_name, soql, tmp_dir)
            except Exception as bulk_exc:  # noqa: BLE001
                markers = (
                    "INVALIDENTITY",
                    "is not supported",
                    "EXCEEDED_ID_LIMIT",
                    "queryMore",
                    "_PermanentBulkError",
                )
                if any(
                    m in str(bulk_exc) or m in type(bulk_exc).__name__ for m in markers
                ):
                    used_bulk = False
                    filepath, row_count = export_object_rest(
                        sf, object_name, soql, tmp_dir
                    )
                else:
                    raise
            s3_key, size = upload_to_s3(
                s3_client,
                filepath,
                object_name,
                cfg.s3_bucket,
                cfg.kms_key_id,
                meta["date_str"],
            )
        logger.info("SFN exported %s: %s rows", object_name, row_count)
        return {
            "object_name": object_name,
            "status": "success",
            "row_count": row_count,
            "s3_key": s3_key,
            "file_size_bytes": size,
            "error": None,
            "used_bulk": used_bulk,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("SFN export failed for %s", object_name)
        return {
            "object_name": object_name,
            "status": "failed",
            "row_count": 0,
            "s3_key": None,
            "file_size_bytes": 0,
            "error": str(exc)[:500],
            "used_bulk": False,
        }


def _sfn_export_pardot(event: dict) -> list:
    """Parallel branch: all Pardot endpoints sequentially (pagination is
    inherently serial). Returns a list of result dicts; [] when disabled."""
    if not event.get("pardot_enabled") or not event.get("pardot_endpoints"):
        logger.info("SFN pardot branch: disabled or nothing to export")
        return []
    cfg = Config.from_env()
    meta = event["meta"]
    s3_client = boto3.client("s3", region_name=cfg.aws_region)
    all_fields = {**PARDOT_EXPORT_OBJECTS, **PARDOT_HIGH_VOLUME_OBJECTS}
    results: list = []
    try:
        secrets = SecretsStore(cfg.secrets_manager_secret_id, cfg.aws_region).get()
        missing = [
            k
            for k in ("pardot_client_secret", "pardot_username", "pardot_password")
            if not secrets.get(k, "").strip()
            or secrets.get(k, "").strip().lower() == "skip"
        ]
        if missing:
            raise RuntimeError(
                f"Pardot enabled but secret missing real values for: {', '.join(missing)}"
            )
        token = get_pardot_token(cfg, secrets)
    except Exception as exc:  # noqa: BLE001
        logger.exception("SFN pardot auth failed")
        return [
            {
                "object_name": "pardot_auth",
                "status": "failed",
                "row_count": 0,
                "s3_key": None,
                "file_size_bytes": 0,
                "error": str(exc)[:500],
            }
        ]

    for endpoint in event["pardot_endpoints"]:
        label = "pardot_" + endpoint.replace("-", "_")
        try:
            fields = all_fields.get(endpoint, PARDOT_MINIMAL_FIELDS)
            with tempfile.TemporaryDirectory(prefix="sfn_pd_") as tmp_dir:
                filepath, row_count = export_pardot_object(
                    token, cfg.pardot_business_unit_id, endpoint, fields, tmp_dir
                )
                s3_key, size = upload_to_s3(
                    s3_client,
                    filepath,
                    label,
                    cfg.s3_bucket,
                    cfg.kms_key_id,
                    meta["date_str"],
                )
            results.append(
                {
                    "object_name": label,
                    "status": "success",
                    "row_count": row_count,
                    "s3_key": s3_key,
                    "file_size_bytes": size,
                    "error": None,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("SFN pardot export failed for %s", label)
            results.append(
                {
                    "object_name": label,
                    "status": "failed",
                    "row_count": 0,
                    "s3_key": None,
                    "file_size_bytes": 0,
                    "error": str(exc)[:500],
                }
            )
    return results


def _sfn_aggregate(event: dict) -> dict:
    """Final step: rebuild the RunReport from all branch results, run the
    volume-anomaly and quota checks, persist the execution log, and send the
    email report - identical outputs to the monolithic run_backup()."""
    cfg = Config.from_env()
    meta = event["meta"]
    report = RunReport(
        run_id=meta["run_id"], started_at=meta["started_at"], mode=meta["mode"]
    )

    for raw in (event.get("sf_results") or []) + (event.get("pardot_results") or []):
        used_bulk = bool(raw.pop("used_bulk", False))
        raw.pop("error", None) if raw.get("error") is None else None
        report.results.append(
            ObjectResult(
                object_name=raw.get("object_name", "unknown"),
                status=raw.get("status", "failed"),
                row_count=raw.get("row_count", 0),
                s3_key=raw.get("s3_key"),
                file_size_bytes=raw.get("file_size_bytes", 0),
                error=raw.get("error"),
            )
        )
        if raw.get("status") == "success" and used_bulk:
            report.bulk_api_jobs_consumed += 1

    finished = datetime.now(timezone.utc)
    report.finished_at = finished.isoformat()
    report.duration_sec = (
        finished - datetime.fromisoformat(meta["started_at"])
    ).total_seconds()

    s3_client = boto3.client("s3", region_name=cfg.aws_region)
    sns_client = (
        boto3.client("sns", region_name=cfg.aws_region) if cfg.sns_topic_arn else None
    )
    ses_client = boto3.client("ses", region_name=cfg.aws_region)

    cw_client = boto3.client("cloudwatch", region_name=cfg.aws_region)
    volume_warning = check_volume_anomaly(
        cw_client, report, cfg.volume_alert_threshold_pct
    )
    if volume_warning:
        report.warnings.append(volume_warning)
        send_alert(
            sns_client,
            cfg.sns_topic_arn,
            "SF Backup: VOLUME ANOMALY detected",
            volume_warning,
        )
    publish_volume_metric(cw_client, report)
    try:
        sf = _sfn_auth(cfg)
        quota_warning = check_bulk_api_quota(sf, report, cfg.bulk_api_quota_alert_pct)
        if quota_warning:
            report.warnings.append(quota_warning)
            send_alert(
                sns_client,
                cfg.sns_topic_arn,
                "SF Backup: Bulk API quota warning",
                quota_warning,
            )
    except Exception as exc:  # noqa: BLE001 - quota check is best-effort
        logger.warning("SFN aggregate: quota check skipped (%s)", exc)

    write_log_to_s3(s3_client, cfg.s3_bucket, report, meta["date_str"], cfg.kms_key_id)

    failed = [r for r in report.results if r.status == "failed"]
    if failed:
        send_alert(
            sns_client,
            cfg.sns_topic_arn,
            f"SF Backup: run {report.run_id} completed with {len(failed)} failure(s)",
            json.dumps([r.__dict__ for r in failed], indent=2),
        )
    send_email_report(ses_client, cfg, report)
    logger.info(
        "SFN run %s finished in %.1fs - %s/%s objects OK",
        report.run_id,
        report.duration_sec,
        len(report.results) - len(failed),
        len(report.results),
    )
    return report.to_json()


def step_handler(event, context):  # noqa: ANN001, ARG001 - AWS Lambda signature
    """Step Functions dispatcher: event["action"] selects the phase."""
    action = (event or {}).get("action")
    if action == "discover":
        return _sfn_discover(event)
    if action == "export_object":
        return _sfn_export_object(event)
    if action == "export_pardot":
        return _sfn_export_pardot(event)
    if action == "aggregate":
        return _sfn_aggregate(event)
    raise ValueError(f"Unknown Step Functions action: {action!r}")


def main() -> int:
    """Container / CLI entry point (ECS Fargate, cron, local runs).

    Mode override - the Fargate equivalent of invoking Lambda with
    {"mode": "full"} - comes from either:
      - env var BACKUP_MODE=full|incremental (EventBridge containerOverrides
        or `aws ecs run-task --overrides ...` for on-demand full exports), or
      - CLI flag --mode full|incremental (local runs).
    Anything else (unset/invalid) falls back to the weekday schedule.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Salesforce -> S3 backup")
    parser.add_argument("--mode", default=os.environ.get("BACKUP_MODE"))
    args, _ = parser.parse_known_args()
    mode = args.mode if args.mode in ("full", "incremental") else None
    if args.mode and mode is None:
        logger.warning("Ignoring invalid mode %r - using weekday schedule", args.mode)

    try:
        result = run_backup(mode_override=mode)
    except Exception:  # noqa: BLE001 - top-level safety net for cron/ECS
        logger.exception("Backup run aborted due to an unhandled error")
        return 1
    return 0 if result["overall_status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
