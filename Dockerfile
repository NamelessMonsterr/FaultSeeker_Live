# FaultSeeker + forensic console - hosted deploy (Render / any Docker host).
# Build from the repository root:  docker build -t faultseeker .
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
ENV DEMO_RUN_TIMEOUT_SECS=7200
ENV FAULTSEEKER_MAX_FUNCTIONS=5
ENV FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS=300
ENV FAULTSEEKER_MODEL_TIME_BUDGET_SECS=600
ENV FAULTSEEKER_SKIP_STRUCTLOGS=1
ENV FAULTSEEKER_SKIP_VIZ=1
WORKDIR /srv

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Foundry `cast` (static binary) - trace fallback when the RPC lacks debug_traceTransaction
RUN curl -fsSL https://github.com/foundry-rs/foundry/releases/download/stable/foundry_stable_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin cast

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY console/app/requirements-app.txt console/app/requirements-app.txt
RUN pip install -r console/app/requirements-app.txt

COPY faultseeker faultseeker
COPY data/models data/models
COPY console/app console/app
COPY console/api console/api

# Seed the offline replay cache (same as run.sh does locally)
RUN mkdir -p /srv/data/cache/forensics \
 && cp console/api/capture /srv/data/cache/forensics/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json

ENV FAULTSEEKER_REPO=/srv \
    FAULTSEEKER_CAPTURE=/srv/console/api/capture \
    HOST=0.0.0.0
# Render injects PORT at runtime; server.py reads it (default 8420).
# DEMO_GATE_PASSWORD must be provided at runtime or every request returns 503.
RUN useradd --uid 10001 --create-home faultseeker \
    && mkdir -p /srv/console/app/runs /srv/logs /srv/data \
    && chown -R faultseeker:faultseeker /srv
USER faultseeker
CMD ["python", "console/app/server.py"]
