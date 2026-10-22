# FaultSeeker forensic console - hosted live deploy (Render / any Docker host)
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Free-tier LLM rate limits (Groq OTPM 1000) can stretch a full run past 25 min.
ENV DEMO_RUN_TIMEOUT_SECS=7200
ENV FAULTSEEKER_MAX_FUNCTIONS=5
# Codex OAuth proxy: route gpt-* models here; medium reasoning calls can exceed 2 min
ENV OPENAI_BASE_URL=https://codex-proxy-render.onrender.com/v1
ENV FAULTSEEKER_LLM_TIMEOUT_SECS=300
ENV FAULTSEEKER_SKIP_STRUCTLOGS=1
ENV FAULTSEEKER_SKIP_VIZ=1
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
ARG FAULTSEEKER_SHA=bc98bfd8cc6903363955da72792db112757172c0
RUN test -n "$FAULTSEEKER_SHA" \
    && git clone --no-checkout --depth 1 --branch "$FAULTSEEKER_REF" "$FAULTSEEKER_REPO" /srv/FaultSeeker- \
    && git -C /srv/FaultSeeker- fetch --depth 1 origin "$FAULTSEEKER_SHA" \
    && git -C /srv/FaultSeeker- checkout --detach "$FAULTSEEKER_SHA" \
    && test "$(git -C /srv/FaultSeeker- rev-parse HEAD)" = "$FAULTSEEKER_SHA"

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
