FROM python:3.11-slim-bookworm

# FAULTSEEKER_PUBLIC makes the server refuse to start with a server-held model key and no access code.
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 HOME=/home/app FAULTSEEKER_PUBLIC=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates build-essential cmake git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 app

# Foundry's `cast` replays transactions. The version is pinned to one the test-suite has been run against, and the
# download is verified against a checksum. To change versions, override BOTH build args (see GUIDE.md, "Foundry").
ARG FOUNDRY_VERSION=v1.9.0
ARG FOUNDRY_SHA256=8d17599b42e3139f1a9c171be3798c4ed8e743ae17b84cc3435e57bf2a51ae99
RUN curl -fsSL -o /tmp/foundry.tgz "https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_amd64.tar.gz" \
 && echo "${FOUNDRY_SHA256}  /tmp/foundry.tgz" | sha256sum -c - \
 && tar -xzf /tmp/foundry.tgz -C /usr/local/bin cast \
 && rm /tmp/foundry.tgz \
 && cast --version

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt && getCode -v

COPY . .
RUN pip install --no-deps -e . && mkdir -p data logs && chown -R app:app /app \
 && chmod +x docker-entrypoint.sh

EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD curl -fsS "http://localhost:${PORT:-10000}/api/health" || exit 1
ENTRYPOINT ["./docker-entrypoint.sh"]
# One worker only (run state lives in this process), and one analysis at a time inside it.
CMD ["sh", "-c", "uvicorn faultseeker.server.app:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
