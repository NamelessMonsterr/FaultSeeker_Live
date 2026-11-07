FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 HOME=/home/app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates build-essential cmake git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 app

# Foundry's `cast` replays transactions. Pin with --build-arg FOUNDRY_VERSION=v1.x.y if you need reproducibility.
ARG FOUNDRY_VERSION=stable
RUN curl -fsSL "https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin --wildcards '*cast' \
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
# One worker only: run state lives in this process.
CMD ["sh", "-c", "uvicorn faultseeker.server.app:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
