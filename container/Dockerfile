# syntax=docker/dockerfile:1

# One backend image for three independently run roles. The image has no default
# command; each service must select one explicitly (see docs/service-images.md):
#   API:       python /app/run_api.py
#   Worker:    python -m dev.run_runtime_worker --health-port 8081
#   Migration: python -m dev.migrate_storage [--check]
# Build from the repository root:  docker build -f container/Dockerfile .
#
# The multi-architecture base image, the build-only uv installer, and the init
# binary are pinned by digest. Update them deliberately and rerun
# dev/check_service_images.py.
ARG TARGETARCH
ARG PYTHON_IMAGE=docker.io/library/python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89

# tini v0.19.0 static release assets; checksums match the release's .sha256sum files.
FROM scratch AS init-amd64
ADD --checksum=sha256:c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-amd64 /tini
FROM scratch AS init-arm64
ADD --checksum=sha256:eae1d3aa50c48fb23b8cbdf4e369d0910dfc538566bfd09df89a774aa84a48b9 \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-arm64 /tini
FROM init-${TARGETARCH} AS init

FROM ${PYTHON_IMAGE} AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY container/build-requirements.txt /tmp/build-requirements.txt
COPY pyproject.toml uv.lock .python-version ./
# Install exactly the locked runtime dependencies. build_ca is an optional complete
# PEM trust bundle for TLS-intercepting build egress, never copied into a layer.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then \
        export SSL_CERT_FILE=/run/secrets/build_ca PIP_CERT=/run/secrets/build_ca; \
    fi && \
    pip install --no-cache-dir --require-hashes --only-binary=:all: \
        -r /tmp/build-requirements.txt && \
    uv sync --locked --no-dev --no-install-project && \
    rm -f /app/.venv/.lock && chmod -R go-w /app/.venv

FROM ${PYTHON_IMAGE}
# Generation writes process-local traces and metrics relative to the working
# directory. Give the service a private scratch directory instead of /app.
RUN groupadd --system --gid 10001 sentrysearch && \
    useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin sentrysearch && \
    install -d -o 10001 -g 10001 -m 0700 /var/lib/sentrysearch
# Root-owned application files. Only the release entry points are copied from
# dev/; test tools, fixtures, the frontend, and local env files are excluded.
COPY --from=init --chmod=0755 /tini /usr/local/bin/tini
COPY --from=build /app/.venv /app/.venv
COPY run_api.py /app/
COPY src /app/src
COPY dev/run_runtime_worker.py dev/migrate_storage.py /app/dev/
COPY certs /app/certs
# Code imports only from /app; PYTHONSAFEPATH keeps the writable working
# directory off sys.path so it cannot shadow application modules.
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONSAFEPATH=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHON_DOTENV_DISABLED=1
WORKDIR /var/lib/sentrysearch
USER 10001:10001
# tini is PID 1: it forwards signals to the selected role's main process only and
# reaps orphaned descendants. The worker supervisor owns its child's drain.
ENTRYPOINT ["/usr/local/bin/tini", "--"]
