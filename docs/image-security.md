# Image security remediation — October 6, 2026

## Current candidate: OS-package minimization

The latest ARM64 image is
`sha256:275b21b7f3ffebfd6b257bff20626c2ed09f8b59dbd17fd77c2f42737ce068f1`
(a local image ID, not a published manifest). It preserves Python 3.11.17 and the
existing dependency lock, using pinned distroless `cc-debian13:nonroot` for the
core and selected native-library payloads from the pinned official Python donor.
This is a project-maintained composition, not an upstream Python 3.11 distroless
distribution. The build rejects mismatched core-library versions. Package
metadata, original checksums and licenses remain; removed command matches are
reviewed, not hidden through scanner suppression.

Trivy 0.75.0, database updated `2026-10-06T19:11:49Z`, scanned this exact image
with the same all-severity/no-ignore/offline/telemetry-disabled settings below.

| Local ARM64 Search candidate | Debian packages | Critical | High | Medium | Low | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Prior Trixie remediation | 87 | 0 | 44 | 58 | 61 | 2 |
| Minimized runtime | 29 | 0 | 7 | 27 | 14 | 1 |

The 49 remaining occurrences represent 39 distinct advisories. No Python-package
findings remain; the unchanged companion runtime image rescans with zero findings.
No remaining match supplies a fixed version in this scan. **Release remains held.**

| Residual group | Evidence and disposition |
| --- | --- |
| Four util-linux high advisories, four matches on `libuuid1` | `mount` and `nsenter` are absent. [76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), [78408](https://security-tracker.debian.org/tracker/CVE-2026-78408), [78409](https://security-tracker.debian.org/tracker/CVE-2026-78409), [78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) concern those commands, not UUID generation. Candidate for an explicit narrow component-absence disposition; not a patched source package or granted waiver. |
| ncurses high, three matches | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) concerns absent `infocmp`. Libraries/terminfo remain for Python curses/readline. The distinct low-severity termcap parser finding remains a library concern; command absence does not cover it. |
| liblzma, scanner UNKNOWN | [Upstream GHSA-5qpq-xqfv-j9pg](https://github.com/tukaani-project/xz/security/advisories/GHSA-5qpq-xqfv-j9pg) is **HIGH**, fixed in 5.8.4; installed Debian `5.8.1-1+deb13u1` remains flagged. It requires repeated decoder initialization after an actual allocation failure for certain non-XZ formats. Ordinary high-level Python decoding creates fresh objects, but explicit repeated `LZMADecompressor.__init__` can reuse state. No application exploit was demonstrated; this is not evidence of safety. Resolve through a supported fix or explicit release-owner risk decision. |
| Medium/low native-library findings | Retained libc, SQLite Session, zlib, libstdc++ and ncurses code needs bounded caller/build/range review. SQLite Session is enabled; absence of the named `apply_v3` symbol does not waive other changeset findings. The zlib `gz_vacate` version-range disagreement remains open. Power8-specific glibc evidence does not apply to this ARM64 image; missing nscd/bzip2recover/zipfile components are narrow findings only. |

The final image passes 13 service-image and 7 named-volume cases: TLS/auth,
least-privilege release separation, init ownership, shutdown, drain/recovery,
absence of shell/package/admin tooling, native Python/spawn compatibility, and
loaded-library package checksums/licenses. A negative control hides only package
metadata and proves the provenance guard fails. The tool-absence guard first
failed on the prior image. Independent final-image inspection resolved all 33
wheel ELF dependency graphs and imported 76 native stdlib extensions; optional
`_tkinter` is absent in both old and new images because Tcl/Tk was already absent.
CA trust, legacy OpenSSL provider, NSS and timezone checks pass. The setup gate
still passes 725 tests with lint, formatting, types and API smoke.

Stop general minimization at this boundary. Do not remove working native stdlib
features, mix Debian unstable packages, overlay core TLS/libc libraries, or erase
metadata to reach zero. Next resolve liblzma and the remaining narrow dispositions,
then finish the environment-specific staging contract. Refresh the exact image
scan before any release decision. amd64 execution, cloud IAM/network/probes,
real providers, registry provenance and production compatibility remain unproven.

## Historical dependency/base remediation receipt

The following records the preceding Trixie candidate, superseded by the exact
image and residual-risk review above. Its counts and next step are historical.

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
