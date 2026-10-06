# Image security remediation — October 6, 2026

The local ARM64 candidate has **zero critical and zero Python-package findings**
in the recorded scan. It is **not release-approved**: 44 high OS package/advisory
matches remain, representing eight distinct advisories. No scanner suppression,
risk waiver, image publication or deployment is part of this receipt.

## Changes

`container/Dockerfile` now uses the official Python 3.11 slim Trixie base, pinned
by multi-architecture index digest. Python remains 3.11.17. The final stage removes
global pip, setuptools, wheel and ensurepip, including their vendored dependencies;
installation remains a build-stage responsibility. It clears unused setuid/setgid
bits without removing OS package metadata or executables. The explicit root-only
volume initializer does not depend on those bits. Application roles remain
UID/GID 10001 with the same read-only filesystem and TLS/auth contracts.

Seven transitive security floors are explicit in `pyproject.toml`, resolved in
`uv.lock`, and exported in `requirements.txt`:

| Package | Before | After |
| --- | --- | --- |
| AnyIO | 4.14.0 | 4.14.2 |
| cryptography | 49.0.0 | 50.0.2 |
| PyJWT | 2.13.0 | 2.15.1 |
| urllib3 | 2.7.0 | 2.8.0 |
| h2 | 4.3.0 | 4.4.1 |
| hpack | 4.1.0 | 4.2.0 |
| multidict | 6.7.1 | 6.9.1 |

The installed package set and Supabase, HTTPX, boto3 and botocore versions remain
unchanged. Supabase authentication still delegates to server-side `get_user`;
these changes introduce no local-JWT authentication path. The targets satisfy
their parent package constraints. PyJWT 2.15.1 preserves valid signature padding
while retaining the security fixes; cryptography 50.0.2 includes its updated
wheel OpenSSL. [PyJWT changelog](https://pyjwt.readthedocs.io/en/stable/changelog.html),
[cryptography changelog](https://cryptography.io/en/latest/changelog/),
[AnyIO changelog](https://anyio.readthedocs.io/en/stable/versionhistory.html),
[urllib3 changelog](https://urllib3.readthedocs.io/en/stable/changelog.html).

## Exact local scan

Final local image ID:
`sha256:b942623160b2fc9858d775e6a30188eb5e0fbbee8e1664e173bdc5a472494f2c`.
This is **not a registry manifest digest**. Do not paste it into an ECR task
definition as a published image reference. Rebuilds may produce a different ID.

Trivy 0.75.0, database updated `2026-10-06T19:11:49Z`, scanned local Docker
with offline dependency resolution, all severities, no ignore file and telemetry
disabled. Raw JSON and CycloneDX SBOMs were retained outside the source tree.
The scanner archive checksum was verified; no signature-attestation claim is made.

| Candidate | Critical | High | Medium | Low | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| Prior Bookworm platform-fit image | 4 | 64 | 126 | 102 | 1 |
| Final Trixie remediation image | 0 | 44 | 58 | 61 | 2 |

Counts are advisory/package occurrences, not unique vulnerabilities or proven
exploits. All final findings are OS matches; the Python result has no findings.
No fixed stable-package version was listed for the remaining high matches.

## Unresolved high findings

The release reviewer owns these open dispositions. Reviewed October 6; review
again before publication against a fresh scan and exact intended image. Do not
mix Debian unstable packages into stable or delete linked libraries ad hoc.

| Source / matches | Advisories and evidence | Disposition |
| --- | --- | --- |
| util-linux / 36 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), [78408](https://security-tracker.debian.org/tracker/CVE-2026-78408), [78409](https://security-tracker.debian.org/tracker/CVE-2026-78409), [78410](https://security-tracker.debian.org/tracker/CVE-2026-78410); mount and nsenter are present. Debian marks Trixie vulnerable/no-dsa. | Open. Removed privilege bits and capability restrictions constrain execution; they do not patch packages. |
| ACL / 1 | [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369); libacl1 is present and linked by cp/tar. Fix deferred, with ABI implications. | Open. Missing setfacl/getfacl does not establish absence of affected library consumers. |
| ncurses / 4 | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720); affected infocmp tool is present; no stable fix listed. | Open. Evaluate unused-tool minimization without breaking Python readline/curses dependencies. |
| systemd / 2 | [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742); libsystemd0/libudev1 present; systemd-homed package/executable absent. | Open for narrow affected-component review, not a blanket systemd exemption. |
| perl-base / 1 | [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538); affected Archive::Tar module absent from inspected system tree and Perl search path. | Open for narrow affected-component review. Preserve the scanner finding; no waiver granted. |

Neither non-root execution nor component-absence evidence establishes exhaustive
transitive reachability. Lower-severity and unknown findings remain in the raw
report and must also receive release review.

## Validation and repeatable gates

The 33 offline regressions in `tests/test_dependency_security.py` cover PEM/HMAC
confusion, valid/invalid JWS padding, retained expiry validation, actual Supabase
SDK parsing, AnyIO IDNA TLS identity, duplicate HTTP/2 Host rejection, bounded
HPACK integer decoding and MultiDict operand lifetime. Focused cases failed
against the old PyJWT, AnyIO, h2, hpack and multidict versions and pass after the
updates. Payloads are bounded; no external provider is called.

The full setup gate passed 725 tests plus lint, formatting, types and API smoke.
The rebuilt ARM64 image passed 9 service-image checks and 7 named-volume checks
on internal Docker networks, including installer absence, zero setuid/setgid bits,
restricted database roles, TLS, shutdown, init ownership, drain and restart recovery.
The companion runtime image passed its 3 ARM64 checks with a refreshed distroless
Debian 13 base and zero scan findings. These are local proofs, not cloud behavior.

To repeat, run `uv run --locked python dev/check_local_setup.py`, then
`uv run --locked python dev/check_service_images.py --runtime-repo <runtime>` and
`uv run --locked python dev/check_platform_fit.py --runtime-repo <runtime>`.
Record the actual rebuilt image IDs; scan those images and retain JSON/SBOMs.
Both image runners build their own tags unless explicitly told to skip builds.
For host consistency checks on macOS, preserve HOME and a valid `LC_ALL=C` locale
while using the fixture-only isolation in `dev/check_runtime_consistency.py`.

No amd64 execution was performed in this slice. No real Supabase, S3, model proxy,
AWS task identity, registry provenance, ECS ordering or production compatibility
was established. An HTTPS proxy, if selected later, needs its own distinct
proxy-versus-destination trust proof. Existing Railway configuration is unchanged;
pushing application dependencies can still trigger its existing deployment hook.

Next: a bounded runtime-package minimization feasibility review and explicit
disposition of residual findings, alongside the environment-specific contract.
Keep publication/deployment held until those decisions and their proofs are complete.
