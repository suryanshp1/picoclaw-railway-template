FROM golang:1.25.8-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src

ARG PICOCLAW_VERSION=v1.0.0

RUN git clone --depth 1 --branch ${PICOCLAW_VERSION} https://github.com/sipeed/picoclaw.git .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux make build

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r picoclaw && useradd -r -g picoclaw picoclaw

COPY --from=builder /src/build/picoclaw /usr/local/bin/picoclaw

COPY requirements.txt /app/requirements.txt
RUN uv pip install --system --no-cache -r /app/requirements.txt

RUN mkdir -p /data/.picoclaw && chown -R picoclaw:picoclaw /data /app

COPY --chown=picoclaw:picoclaw server.py /app/server.py
COPY --chown=picoclaw:picoclaw templates/ /app/templates/
COPY --chown=picoclaw:picoclaw start.sh /app/start.sh
RUN chmod +x /app/start.sh

USER picoclaw

ENV HOME=/data
ENV PICOCLAW_AGENTS_DEFAULTS_WORKSPACE=/data/.picoclaw/workspace

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

CMD ["/app/start.sh"]