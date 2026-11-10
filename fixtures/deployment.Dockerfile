FROM ghcr.io/astral-sh/uv:0.8.24@sha256:1d31be550ff927957472b2a491dc3de1ea9b5c2d319a9cea5b6a48021e2990a6 AS uv
FROM registry.k8s.io/kubectl:v1.34.1@sha256:59bafa07ff3a6d4b417e7633ddb9d79a9606ca98bf64bac080b3e65748669250 AS kubectl
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
COPY --from=uv /uv /usr/local/bin/uv
COPY --from=kubectl /bin/kubectl /usr/local/bin/kubectl
WORKDIR /opt/birbverify
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --no-cache --python /usr/local/bin/python
ENV PATH="/opt/birbverify/.venv/bin:$PATH"
USER 10001:10001
ENTRYPOINT ["python", "-m"]
CMD ["birbverify.deployment_audit", "--help"]
