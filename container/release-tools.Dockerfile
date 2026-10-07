# syntax=docker/dockerfile:1

# Release-tools image: guarded bootstrap, grant, proof and reconciliation jobs
# (docs/release-tools.md). Nonroot by default, no shell, no package manager and no
# network fetch at run time. Each job selects one fixed command:
#   bootstrap | grant | proof | reconcile   (digest prints the build pins)
# Build from the repository root:
#   docker build -f container/release-tools.Dockerfile .
#
# Every input is pinned by digest or checksum: the distroless runtime base, the
# Python donor, the PostgreSQL client donor and the init binary. psql and its
# libraries are preserved as whole Debian packages with their metadata so scans
# see them. Update a pin deliberately and rerun dev/check_release_tools.py, which
# also proves inside the built image that every ELF object resolves locally.
ARG TARGETARCH
ARG PYTHON_IMAGE=docker.io/library/python:3.11-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce
ARG POSTGRES_IMAGE=docker.io/library/postgres:16.15-trixie@sha256:65b16a8b326e0cfbdf33fa7e783f2a0cb352a61448616ccccfd616ef42aa0f65
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

FROM ${POSTGRES_IMAGE} AS psql-files
COPY --from=runtime-base /var/lib/dpkg/status.d /tmp/base-status
# The client and libpq revisions were reviewed together. Shared native libraries
# come from the distroless base and must be the exact revisions psql was built
# against in this donor; never overlay libc or OpenSSL from the donor.
RUN --network=none set -eu; \
    test "$(dpkg-query -W -f='${Version}' postgresql-client-16)" = '16.15-1.pgdg13+2'; \
    test "$(dpkg-query -W -f='${Version}' libpq5)" = '18.6-1.pgdg13+2'; \
    for package in libc6 libssl3t64 zlib1g libzstd1; do \
        expected="$(sed -n 's/^Version: //p' "/tmp/base-status/$package")"; \
        test "$(dpkg-query -W -f='${Version}' "$package")" = "$expected"; \
    done
# Preserve whole packages, with status and md5sums, for psql's library closure.
# The slim donor already drops docs (except licenses), manuals and translations.
RUN --network=none set -eu; \
    mkdir -p /runtime-extra/var/lib/dpkg/status.d; \
    for package in postgresql-client-16 libpq5 libreadline8t64 readline-common libtinfo6 \
        libgssapi-krb5-2 libkrb5-3 libk5crypto3 libkrb5support0 libcom-err2 \
        libkeyutils1 libldap2 libsasl2-2; do \
        dpkg-query --listfiles "$package" > /tmp/package-listed; \
        : > /tmp/package-files; \
        while IFS= read -r path; do \
            if [ -e "$path" ] || [ -L "$path" ]; then \
                printf '%s\n' "$path" >> /tmp/package-files; \
            else \
                case "$path" in /usr/share/doc/*|/usr/share/man/*|/usr/share/info/*|/usr/share/lintian/*|/usr/share/locale/*|/usr/share/postgresql/16/man/*) ;; \
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
    find /runtime-extra/usr/lib/postgresql/16/bin -mindepth 1 ! -name psql -delete; \
    rm -r /runtime-extra/usr/share/postgresql/16/man
# Only psql is kept from the client package; its other programs are removed but
# the package metadata stays, so scanners may overmatch them (review, not suppress).

FROM ${PYTHON_IMAGE} AS python-files
COPY --from=runtime-base /var/lib/dpkg/status.d /tmp/base-status
COPY --from=runtime-base /etc/passwd /etc/group /tmp/base-etc/
RUN --network=none set -eu; \
    for package in libc6 libssl3t64 libgcc-s1 libstdc++6 zlib1g libzstd1; do \
        expected="$(sed -n 's/^Version: //p' "/tmp/base-status/$package")"; \
        test "$(dpkg-query -W -f='${Version}' "$package")" = "$expected"; \
    done
# Interpreter and standard library only. Installers, headers, the stable-ABI shim
# (no abi3 extensions are shipped) and the stdlib extension modules whose native
# libraries this image does not ship (or that exist only for CPython's own tests)
# are removed instead of left unresolvable.
RUN --network=none set -eu; \
    python -m pip uninstall --yes pip setuptools wheel; \
    rm -r /usr/local/lib/python3.11/ensurepip /usr/local/include /usr/local/lib/pkgconfig; \
    rm /usr/local/bin/python3-config /usr/local/bin/python3.11-config \
        /usr/local/lib/libpython3.so; \
    cd /usr/local/lib/python3.11/lib-dynload; \
    for module in _bz2 _lzma _sqlite3 _curses _curses_panel _dbm _gdbm _ctypes \
        _ctypes_test _uuid _crypt _tkinter readline _testbuffer _testcapi _testclinic \
        _testimportmultiple _testinternalcapi _testmultiphase _xxtestfuzz xxlimited \
        xxlimited_35; do \
        rm "$module".cpython-311-*-linux-gnu.so; \
    done
# Jobs run as distroless nonroot (65532) or as the Search image's uid (10001) so
# each reads only its own init-prepared, owner-only trust material.
RUN --network=none set -eu; \
    mkdir /out; cp /tmp/base-etc/passwd /tmp/base-etc/group /out/; \
    grep -q '^nonroot:x:65532:' /out/passwd; \
    printf 'sentrysearch:x:10001:10001:sentrysearch:/nonexistent:/sbin/nologin\n' >> /out/passwd; \
    printf 'sentrysearch:x:10001:\n' >> /out/group

FROM runtime-base AS release-tools
COPY --from=psql-files /runtime-extra/ /
COPY --from=python-files /usr/local/ /usr/local/
COPY --from=python-files /out/passwd /out/group /etc/
COPY --from=init --chmod=0755 /tini /usr/local/bin/tini
# Root-owned, read-only programs and SQL; bytecode is never written at run time.
COPY release_tools /usr/local/lib/python3.11/site-packages/release_tools
ENV HOME=/nonexistent
WORKDIR /
USER 65532:65532
# tini is PID 1 and forwards stop signals to the job; the job's watchdog stops
# and reaps psql's whole process group. -I ignores PYTHON* environment and the
# working directory; -B never writes bytecode on the read-only root.
ENTRYPOINT ["/usr/local/bin/tini", "--", "/usr/local/bin/python3.11", "-I", "-B", "-m", "release_tools"]
# No default job: each task definition selects exactly one command.
CMD []
