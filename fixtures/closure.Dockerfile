FROM docker:28.3.3-cli AS dockercli
FROM python:3.13-slim-bookworm
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates procps ripgrep && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.8.24 && ln -s /usr/local/bin/docker /usr/bin/docker
