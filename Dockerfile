# FaultSeeker forensic console - hosted live deploy (Render / any Docker host)
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Foundry `cast` (static binary) - trace fallback when the RPC lacks debug_traceTransaction
RUN curl -fsSL https://github.com/foundry-rs/foundry/releases/download/stable/foundry_stable_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin cast

# FaultSeeker pipeline source: the user's own fork (public repo, no secrets).
# Pinned to the console-demo-compat branch until that PR merges into main.
ARG FAULTSEEKER_REPO=https://github.com/NamelessMonsterr/FaultSeeker-.git
ARG FAULTSEEKER_REF=console-demo-compat
# Bump this SHA to the fork commit to deploy: the changed ARG value invalidates
# the Docker layer cache so the clone below re-runs (clone --branch needs a
# branch/tag name, not a raw SHA).
ARG FAULTSEEKER_SHA=c16c45c4bb8601ea5cfa77d2f1dd0e6193a852aa
RUN echo "deploying fork commit $FAULTSEEKER_SHA"  && git clone --depth 1 --branch "$FAULTSEEKER_REF" "$FAULTSEEKER_REPO" /srv/FaultSeeker-

RUN pip install -r /srv/FaultSeeker-/requirements.txt
COPY app/requirements-app.txt app/requirements-app.txt
RUN pip install -r app/requirements-app.txt

COPY app app
COPY api api
# Seed the offline replay cache (same as run.sh does locally)
RUN mkdir -p /srv/FaultSeeker-/data/cache/forensics \
 && cp api/capture /srv/FaultSeeker-/data/cache/forensics/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json

ENV FAULTSEEKER_REPO=/srv/FaultSeeker- \
    FAULTSEEKER_CAPTURE=/srv/api/capture \
    HOST=0.0.0.0
# Render injects PORT at runtime; server.py reads it (default 8420).
CMD ["python", "app/server.py"]
