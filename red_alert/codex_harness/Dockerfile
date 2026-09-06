FROM node:22-bookworm-slim

ARG CODEX_VERSION=0.153.4

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global "@openai/codex@${CODEX_VERSION}"

COPY red-alert-harness.config.toml /opt/red-alert-codex/red-alert-harness.config.toml
COPY red-alert-harness.config.toml /etc/codex/config.toml
COPY requirements.toml /etc/codex/requirements.toml
COPY entrypoint.sh /usr/local/bin/red-alert-codex-entrypoint

RUN chmod 0444 \
        /opt/red-alert-codex/red-alert-harness.config.toml \
        /etc/codex/config.toml \
        /etc/codex/requirements.toml \
    && chmod 0555 /usr/local/bin/red-alert-codex-entrypoint

ENV CODEX_HOME=/codex-home
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/red-alert-codex-entrypoint"]
