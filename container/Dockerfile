# syntax=docker/dockerfile:1

# One backend image for independently run roles. The image has no default
# command; each service must select one explicitly (see docs/service-images.md):
#   API:       python /app/run_api.py
#   Worker:    python -m dev.run_runtime_worker --health-port 8081
#   Migration: python -m dev.migrate_storage [--check]
#   Volume init: python -m dev.prepare_service_volumes ... (explicit root override)
# Build from the repository root:  docker build -f container/Dockerfile .
#
# The multi-architecture base image, the build-only uv installer, and the init
# binary are pinned by digest. Update them deliberately and rerun
# dev/check_service_images.py.
ARG TARGETARCH
ARG PYTHON_IMAGE=docker.io/library/python:3.11-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

# tini v0.19.0 static release assets; checksums match the release's .sha256sum files.
FROM scratch AS init-amd64
ADD --checksum=sha256:c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-amd64 /tini
FROM scratch AS init-arm64
ADD --checksum=sha256:eae1d3aa50c48fb23b8cbdf4e369d0910dfc538566bfd09df89a774aa84a48b9 \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-arm64 /tini
FROM init-${TARGETARCH} AS init
FROM ${RUNTIME_IMAGE} AS runtime-base

# TODO(liblzma-backport): remove the local package stages after an authenticated
# fixed Trixie package passes docs/liblzma-backport.md replacement gates.
FROM ${PYTHON_IMAGE} AS liblzma-source
WORKDIR /work
COPY container/liblzma /inputs
COPY container/liblzma/debian.sources /etc/apt/sources.list.d/debian.sources
# Historical dated snapshots retain signature verification. Verify their exact
# Release hashes too, then authenticate and hash-pin the original Debian source.
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then \
        export SSL_CERT_FILE=/run/secrets/build_ca; \
        printf 'Acquire::https::CaInfo "/run/secrets/build_ca";\n' > /tmp/apt-ca.conf; \
        export APT_CONFIG=/tmp/apt-ca.conf; \
    fi && \
    apt-get update --error-on=any && python /inputs/recipe.py indexes && \
    apt-get install -y --no-install-recommends dpkg-dev && \
    apt-get build-dep -y --arch-only --no-install-recommends xz-utils=5.8.1-1+deb13u1 && \
    apt-get source --download-only xz-utils=5.8.1-1+deb13u1 && \
    python /inputs/recipe.py prepare && rm -f /tmp/apt-ca.conf

FROM liblzma-source AS liblzma-build
# Fixed changelog time plus SOURCE_DATE_EPOCH stabilizes package timestamps.
ENV SOURCE_DATE_EPOCH=1791331140
WORKDIR /work/xz
RUN --network=none dpkg-buildpackage -B -us -uc -j2 && \
    python /inputs/recipe.py export
RUN --network=none mkdir -p /probe && \
    cc -std=c11 -Wall -Wextra -Werror -O2 -fstack-protector-strong \
        -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now \
        -I/work/xz/src/liblzma/api /inputs/decoder_reinit_test.c \
        -Wl,-l:liblzma.so.5 -o /probe/decoder_reinit_test && \
    cp /work/xz/tests/files/good-unknown_size-with_eopm.lzma /probe/

# Exportable evidence and test tools never enter the service image.
FROM scratch AS liblzma-package
COPY --from=liblzma-build /out/ /
FROM scratch AS liblzma-test-tools
COPY --from=liblzma-build /probe/ /probe/

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

FROM ${PYTHON_IMAGE} AS runtime-files
COPY --from=liblzma-build /out/liblzma5.deb /tmp/liblzma5.deb
# Fail on donor drift: do not replace a future official fix with this older fork.
RUN --network=none test "$(dpkg-query -W -f='${Version}' liblzma5)" = '5.8.1-1+deb13u1' && \
    dpkg --path-include='/usr/share/doc/liblzma5/*' -i /tmp/liblzma5.deb && \
    rm /tmp/liblzma5.deb
COPY --from=liblzma-build /out/liblzma-backport.json /runtime-extra/usr/share/sentrysearch/liblzma-backport.json
COPY --from=runtime-base /var/lib/dpkg/status.d /tmp/base-status
# These exact revisions were reviewed together. Fail rather than overlay libc or
# silently mix different native TLS/loader versions when either pin changes.
RUN set -eu; for package in libc6 libssl3t64 libgcc-s1 libstdc++6 zlib1g libzstd1; do \
    expected="$(sed -n 's/^Version: //p' "/tmp/base-status/$package")"; \
    test "$(dpkg-query -W -f='${Version}' "$package")" = "$expected"; \
    done
# Dependency installation belongs only in the build stage. Remove global
# installers, their vendored libraries and ensurepip's bundled wheels, not just
# their entry points. The application venv does not include packaging tools.
RUN python -m pip uninstall --yes pip setuptools wheel && \
    rm -r /usr/local/lib/python3.11/ensurepip /usr/local/include /usr/local/lib/pkgconfig && \
    rm /usr/local/bin/python3-config /usr/local/bin/python3.11-config
# Preserve whole native-library packages required by the existing Python stdlib,
# including UUID, curses and DBM. Do not copy the builder's libc/OpenSSL over the
# distroless base. The base owns those, C++ libs, NSS, netbase, CA and timezone.
# Keep package provenance and licenses so minimization never hides scan matches.
RUN set -eu; \
    mkdir -p /runtime-extra/var/lib/dpkg/status.d; \
    for package in libbz2-1.0 libcrypt1 libdb5.3t64 libffi8 libgdbm6t64 \
        liblzma5 libncursesw6 libreadline8t64 libsqlite3-0 libtinfo6 libuuid1 \
        readline-common ncurses-base openssl-provider-legacy openssl; do \
        dpkg-query --listfiles "$package" > /tmp/package-listed; \
        : > /tmp/package-files; \
        while IFS= read -r path; do \
            if [ -e "$path" ] || [ -L "$path" ]; then \
                printf '%s\n' "$path" >> /tmp/package-files; \
            else \
                case "$path" in /usr/share/doc/*|/usr/share/man/*|/usr/share/info/*|/usr/share/lintian/*) ;; \
                    *) printf 'Missing package runtime file: %s\n' "$path" >&2; exit 1 ;; esac; \
            fi; \
        done < /tmp/package-listed; \
        test -f "/usr/share/doc/$package/copyright"; \
        tar --create --no-recursion --verbatim-files-from \
            --files-from=/tmp/package-files --file=/tmp/package.tar; \
        tar --extract --file=/tmp/package.tar --directory=/runtime-extra; \
        dpkg-query --status "$package" > "/runtime-extra/var/lib/dpkg/status.d/$package"; \
        binary_package="$(dpkg-query -W -f='${binary:Package}' "$package")"; \
        cp "/var/lib/dpkg/info/$binary_package.md5sums" \
            "/runtime-extra/var/lib/dpkg/status.d/$package.md5sums"; \
    done; \
    rm /runtime-extra/usr/bin/openssl /runtime-extra/usr/bin/c_rehash \
        /runtime-extra/usr/lib/ssl/misc/CA.pl /runtime-extra/usr/lib/ssl/misc/tsget.pl \
        /runtime-extra/usr/lib/ssl/misc/tsget
# The donor already prunes changelogs/manpages. Preserve all remaining package
# files except OpenSSL CLI/Perl helpers: only config, providers and licenses are
# needed at runtime. Keep its package metadata too; scanners may overmatch the
# absent commands, which requires evidence review rather than suppression.
# Cloudflare-only extras, used by the cloudflare target and never by the default
# image: util-linux setpriv (only that file, with util-linux's package metadata
# so scanners still see the version), its whole libcap-ng0 library package, and
# empty root-owned directories the entrypoint fills before dropping privileges.
RUN --network=none set -eu; \
    root=/cloudflare-extra; \
    mkdir -p "$root/usr/bin" "$root/usr/share/doc/util-linux" "$root/var/lib/dpkg/status.d" \
        "$root/run/material" "$root/run/tmp" "$root/run/work"; \
    test "$(dpkg -S /usr/bin/setpriv)" = 'util-linux: /usr/bin/setpriv'; \
    cp -p /usr/bin/setpriv "$root/usr/bin/setpriv"; \
    cp -p /usr/share/doc/util-linux/copyright "$root/usr/share/doc/util-linux/copyright"; \
    dpkg-query --status util-linux > "$root/var/lib/dpkg/status.d/util-linux"; \
    grep '  usr/bin/setpriv$' "/var/lib/dpkg/info/$(dpkg-query -W -f='${binary:Package}' util-linux).md5sums" \
        > "$root/var/lib/dpkg/status.d/util-linux.md5sums"; \
    dpkg-query --listfiles libcap-ng0 > /tmp/capng-listed; \
    : > /tmp/capng-files; \
    while IFS= read -r path; do \
        if [ -e "$path" ] || [ -L "$path" ]; then printf '%s\n' "$path" >> /tmp/capng-files; fi; \
    done < /tmp/capng-listed; \
    tar --create --no-recursion --verbatim-files-from --files-from=/tmp/capng-files --file=/tmp/capng.tar; \
    tar --extract --file=/tmp/capng.tar --directory="$root"; \
    dpkg-query --status libcap-ng0 > "$root/var/lib/dpkg/status.d/libcap-ng0"; \
    cp "/var/lib/dpkg/info/$(dpkg-query -W -f='${binary:Package}' libcap-ng0).md5sums" \
        "$root/var/lib/dpkg/status.d/libcap-ng0.md5sums"
# Generation writes process-local traces and metrics relative to the working
# directory. Give the service a private scratch directory instead of /app.
RUN groupadd --system --gid 10001 sentrysearch && \
    useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin sentrysearch && \
    install -d -o 10001 -g 10001 -m 0700 /var/lib/sentrysearch

FROM runtime-base AS service
COPY --from=runtime-files /runtime-extra/ /
COPY --from=runtime-files /usr/local/ /usr/local/
COPY --from=runtime-files /etc/passwd /etc/group /etc/
COPY --from=runtime-files /var/lib/sentrysearch /var/lib/sentrysearch
# Root-owned application files. Only service and bootstrap entry points are copied from
# dev/; test tools, fixtures, the frontend, and local env files are excluded.
COPY --from=init --chmod=0755 /tini /usr/local/bin/tini
COPY --from=build /app/.venv /app/.venv
COPY run_api.py /app/
COPY src /app/src
# Artifact storage shares the R2 client with the release controller's control store.
COPY release_cloudflare/__init__.py release_cloudflare/r2_client.py /app/release_cloudflare/
COPY dev/run_runtime_worker.py dev/migrate_storage.py dev/prepare_service_volumes.py dev/check_worker_readiness.py /app/dev/
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
# Distroless has no default role; never inherit a command from a future base.
CMD []

# Cloudflare Durable Object container image (`--target cloudflare`). It has no
# init container or secret volume and runs every process with root-equivalent
# capabilities, so it starts as root: sentrysearch_cloudflare.cfinit writes the
# role's material, then setpriv drops every capability set and switches to
# 10001 before the role runs. See deploy/cloudflare/README.md.
FROM service AS cloudflare
COPY --from=runtime-files /cloudflare-extra/ /
COPY deploy/cloudflare/sentrysearch_cloudflare /app/sentrysearch_cloudflare
USER 0:0
# No entrypoint or command: start({entrypoint}) is documented only as the
# "command and arguments to run", and local workerd appends it to an image
# entrypoint. With neither set, the Durable Object's complete fixed argv, which
# begins with the wrapper, runs the same way under either reading, and a start
# without it has no command at all.
ENTRYPOINT []
CMD []

# The default build target is the service image without the Cloudflare wrapper.
FROM service
