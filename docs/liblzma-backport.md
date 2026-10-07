# Temporary liblzma security backport

Owner: **SentrySearch maintainers**. This is a local package build, not an
official Debian release, a scanner exception, or deployment approval.

`TODO(liblzma-backport)`: remove the local package recipe and its backport-only
assertions after an authenticated official Trixie package fixes the advisory and
passes the replacement gates below. Retain the behavioral regression tests.
Do not copy or extend this temporary package-maintenance path for other libraries.

## Why this exists

[GHSA-5qpq-xqfv-j9pg](https://github.com/tukaani-project/xz/security/advisories/GHSA-5qpq-xqfv-j9pg)
concerns decoder state after allocation failure and repeated initialization.
The upstream advisory is HIGH even when a scanner labels it UNKNOWN.
The last official-package check on October 6, 2026 found
`xz-utils=5.8.1-1+deb13u1` in Trixie and no replacement in Trixie security,
updates, or proposed-updates. Recheck the
[Debian tracker](https://security-tracker.debian.org/tracker/TEMP-1147318-639065)
and authenticated package indexes before updating this recipe.

The bounded patch set retains Debian's existing patches and adds these exact
upstream commits:

| Purpose | Commit |
| --- | --- |
| Safe reinitialization after decoder allocation failure | [fe4d763d566a38ad61d4c5022520c25578a3a464](https://github.com/tukaani-project/xz/commit/fe4d763d566a38ad61d4c5022520c25578a3a464) |
| Cleanup after filter-chain initialization failure | [e5e63d50eac1b4357a5a7a0abd3c5f99a5c47881](https://github.com/tukaani-project/xz/commit/e5e63d50eac1b4357a5a7a0abd3c5f99a5c47881) |
| Upstream regression test | [ff834f25ae4f9b3e6270d41b4c843b8b1183346c](https://github.com/tukaani-project/xz/commit/ff834f25ae4f9b3e6270d41b4c843b8b1183346c) |

The recipe does not upgrade the upstream library version or remove Python's
`lzma` module. The honest local Debian version is
`5.8.1-1+deb13u1+sentry1`. A scanner may still associate that version with the
advisory; changing package metadata to manufacture a clean scan is not allowed.

## Pinned build and provenance

`container/Dockerfile` and `container/liblzma/manifest.json` are the source of
truth. The build uses the digest-pinned official Python 3.11 Trixie donor,
Debian snapshot `20261006T203214Z` for `trixie`/`trixie-updates`, and security
snapshot `20261006T205323Z` for `trixie-security`.

APT verifies Debian archive signatures. `recipe.py indexes` additionally requires
the exact three reviewed `InRelease` hashes, before dependency installation.
`Check-Valid-Until: no` applies only to the historical snapshot sources; signature,
TLS, and content-hash checks remain enabled. No live-repository fallback is used.

`recipe.py prepare` verifies the original `.dsc`, original archive, detached
signature file, Debian archive, and each checked-in patch by SHA-256. Patches
apply with zero fuzz and become a recorded Debian source patch. The detached
upstream signature is preserved and hash-checked; this is **not** a claim that
the recipe independently verifies its author's signature. Debian archive
authentication is the verified source-distribution trust chain.

The builder installs architecture-dependent build requirements and runs
`dpkg-buildpackage -B -us -uc -j2` without network. This retains Debian packaging,
ABI/hardening checks, and normal/static/xzdec tests while omitting documentation-only
build dependencies. The changelog time and `SOURCE_DATE_EPOCH` are fixed. Build
records are exported unsigned; no signing key or signing claim is involved.

| Stage | Output / boundary |
| --- | --- |
| `liblzma-source` | Authenticated source and build dependencies; source/patch validation |
| `liblzma-build` | Compiled package, source/build records, and native test tool |
| `liblzma-package` | Export-only package/evidence files; not a runnable service |
| `liblzma-test-tools` | Export-only `/probe` executable and small upstream fixture |
| `runtime-files` → `service` | Installs the local package before copying its runtime files, checksums, license and provenance into the final image |

The donor's original `liblzma5` version must equal `5.8.1-1+deb13u1`, or the
build fails rather than overwriting a newer official package. The service image
keeps `/usr/share/sentrysearch/liblzma-backport.json` with input IDs, architecture,
package SHA-256 and shared-library SHA-256. Test executables, fixtures, source,
compilers and package-management tools do not enter that image.

## Repeatable local checks

Run from the repository root with Docker/BuildKit, `uv`, and a compatible
SentryRuntime checkout. These commands are verification procedures, not recorded
results for a newly built image. Existing local evaluation evidence is ARM64;
an `amd64` pin or architecture-aware code is not executed AMD64 proof.

```bash
uv run python -m pytest tests/test_liblzma_recipe.py tests/test_service_image_runner.py -v
DOCKER_DEFAULT_PLATFORM=linux/arm64 uv run python dev/check_service_images.py --runtime-repo ../sentryruntime
```

The service runner builds both services and `liblzma-test-tools`, resolves their
immutable local image IDs, and runs `tests/service_images.py`,
`tests/platform_fit.py`, and `tests/liblzma_backport.py`. For a TLS-intercepting
build proxy, add `--build-ca-file /path/to/complete-ca-bundle.pem` to the runner;
never disable TLS verification. The optional trust bundle is a build secret,
not a runtime image file.

The native regression uses a controlled allocator that rejects allocations of
at least 1 MiB: decode a small dictionary, reject an 8 MiB dictionary with
`LZMA_MEM_ERROR`, then reuse the stream and decode successfully. Separate `alone`
and `auto` cases require identical recovered output, observed injected rejection,
balanced allocations/frees, and zero remaining allocations. The container is
network-disabled, read-only, non-root, capability-free, memory/PID-bounded, and
has core dumps disabled. A container OOM is rejected as invalid evidence.
The probe is mounted read-only for the test, not shipped in the service.

Python checks cover raw/XZ/alone round trips, concatenated streams, seek/close,
incremental decoding, invalid/truncated input, memory limits, and explicit
decoder reinitialization. These are wrapper compatibility checks, not injected
Python allocation-failure tests. The native suite does not claim direct lzip or
MicroLZMA coverage, sanitizer coverage, or exhaustive allocation-failure coverage.
Metadata assertions separately verify the local version, package checksums,
license, provenance, and actual Python linkage to the installed shared library.

### Export the package, exact source and build records

The export target contains `liblzma5.deb`, original and patched source records
(`.dsc`, archives and original `.asc`), `.buildinfo`, `.changes`,
`build-packages.txt`, and `liblzma-backport.json`. Keep these together; the small
runtime provenance record is not a substitute for complete corresponding source.
This is not a complete Debian binary-upload set: `.changes` also names utility,
development and debug packages that are not exported, and names the versioned
library package while this target exports it as `liblzma5.deb`.

```bash
liblzma_evidence_dir=$(mktemp -d)
docker buildx build --platform linux/arm64 --file container/Dockerfile \
  --target liblzma-package --no-cache-filter liblzma-build \
  --output "type=local,dest=${liblzma_evidence_dir}/first" .
docker buildx build --platform linux/arm64 --file container/Dockerfile \
  --target liblzma-package --no-cache-filter liblzma-build \
  --output "type=local,dest=${liblzma_evidence_dir}/second" .
cmp "${liblzma_evidence_dir}/first/liblzma5.deb" \
    "${liblzma_evidence_dir}/second/liblzma5.deb"
shasum -a 256 "${liblzma_evidence_dir}/first/liblzma5.deb" \
              "${liblzma_evidence_dir}/second/liblzma5.deb"
```

For build egress that requires the extra CA, add
`--secret id=build_ca,src=/path/to/complete-ca-bundle.pem` to each build.
`--no-cache-filter liblzma-build` forces two fresh compilations from the pinned
source/dependency stage; it does not force two independent downloads of that
stage. Require matching package bytes, retain both inventories/build records,
and investigate any mismatch. `.buildinfo` wall-clock fields may differ.
This package comparison does not assert reproducible whole-image digests.
Retain the export directory explicitly with the release evidence before cleaning
up temporary files.

## Replace with the official Debian package

`TODO(liblzma-backport)`: SentrySearch maintainers must perform this removal as
one reviewed change after all of these gates pass:

1. Verify a fixed package is available from an authenticated official Trixie
   stable/security/updates source. Check its actual patch/source content and
   advisory disposition, not merely a higher version string. Proposed-updates
   availability alone is not an accepted stable replacement.
2. Select reviewed donor/base pins with compatible native-library revisions.
   The current donor-version guard should fail until deliberately removed or
   replaced; never bypass it to keep applying this older local fork.
3. Re-run the native allocator regression and Python compatibility suite against
   the official candidate's real loaded library, plus the complete service and
   platform-fit suites. Rebuild and test every intended release architecture;
   ARM64 results cannot stand in for AMD64.
4. Remove the local source/patch/manifest recipe, snapshot-only build inputs,
   local-package installation/provenance copy, backport-only package stages,
   `tests/test_liblzma_recipe.py`, and local-version/manifest-only assertions.
   Keep ordinary package provenance/checksum/license assertions.
5. **Retain** the allocator and Python behavioral tests. Move the minimal native
   probe and fixture preparation into an ordinary test-only build stage that
   uses authenticated official development inputs. Update the service runner's
   tool target and target-name-specific unit test; do not leave tests depending
   on the deleted backport stages or ship their tools in the release image.
6. Export fresh source/provenance as required, create a new SBOM and scan the exact
   candidate image, and review all remaining advisories without suppressions.
   Update these documents and remove every `TODO(liblzma-backport)` marker only
   when the temporary path has actually gone.

Passing this regression resolves a bounded decoder behavior, not the independent
release decision for all image findings. See [image security](image-security.md)
for that gate. No command here publishes an image, deploys a service, changes
production, or grants a vulnerability waiver.
