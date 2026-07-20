# Salesforce -> S3 backup task image (ECS Fargate)
# Build:  docker build -t salesforce-backup .
# The container runs one backup then exits - it is a scheduled task, not a service.
FROM public.ecr.aws/docker/library/python:3.12-slim

# Non-root user - least privilege inside the container.
# `id -u backup` guards against base images that already ship a same-named
# user (seen on some python:3.12-slim rebuilds) - useradd would otherwise
# fail the build with "user already exists".
RUN id -u backup >/dev/null 2>&1 || useradd --create-home --shell /usr/sbin/nologin backup
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The prod script keeps its lambda_handler (harmless here); main() is the
# container entry point and reads BACKUP_MODE / --mode for full-run overrides.
# Context = src/backup/ (repo layout), where the script is already named
# salesforce_backup.py - this same Dockerfile serves the Fargate exit plan
# AND the CI image scan (LZv2 security-scan docker jobs build it every PR).
COPY salesforce_backup.py ./salesforce_backup.py

USER backup

# Unbuffered stdout so CloudWatch (awslogs driver) receives lines in real time
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "salesforce_backup.py"]