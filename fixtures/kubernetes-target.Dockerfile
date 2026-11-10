FROM registry.k8s.io/kubectl:v1.34.1@sha256:59bafa07ff3a6d4b417e7633ddb9d79a9606ca98bf64bac080b3e65748669250 AS kubectl
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
COPY --from=kubectl /bin/kubectl /usr/local/bin/kubectl
WORKDIR /opt/birbverify
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home birbverify
USER 10001:10001
ENTRYPOINT ["python", "-m", "birbverify.kubernetes_service"]
