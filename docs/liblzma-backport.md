# liblzma: the official Debian fix (formerly a local backport)

Owner: **SentrySearch maintainers**. The service image carries Debian's own
fixed `liblzma5`. This file keeps its earlier name so existing links resolve;
the local backport it used to describe is gone.

## What the image carries

[GHSA-5qpq-xqfv-j9pg](https://github.com/tukaani-project/xz/security/advisories/GHSA-5qpq-xqfv-j9pg)
concerns decoder state after allocation failure and repeated initialization.
The upstream advisory is HIGH even when a scanner labels it UNKNOWN. Debian
fixed it in `xz-utils 5.8.1-1+deb13u2`, published to `trixie-security` as
DSA-6549-1 ([tracker](https://security-tracker.debian.org/tracker/TEMP-1147318-639065)).

The digest-pinned Python 3.11 Trixie donor image still carries
`liblzma5 5.8.1-1+deb13u1`. The build installs the official
`5.8.1-1+deb13u2` package over it and copies that package's files, checksums
and license into the final image, as it does for every other native-library
package. The library is unmodified: no local patch, version suffix or
provenance file. Python's `lzma` module is unchanged and loads it.

This replaces the local build of `5.8.1-1+deb13u1+sentry1` that the image
carried from October 6 to October 12, 2026, while no official fix existed.

## Replace with the official Debian package

Done on October 12, 2026. This section used to list the conditions for the
replacement; it now records what was checked before making it.

| Check | Result |
| --- | --- |
| Official source | `5.8.1-1+deb13u2` is in the signed `trixie-security` index of the dated snapshot below, first archived there on 2026-10-07. Proposed-updates was not used. |
| Patch content, not the version string | The package's `debian/patches` carry upstream commits [fe4d763](https://github.com/tukaani-project/xz/commit/fe4d763d566a38ad61d4c5022520c25578a3a464) and [e5e63d5](https://github.com/tukaani-project/xz/commit/e5e63d50eac1b4357a5a7a0abd3c5f99a5c47881) as cherry-picks. Their changed lines are identical to the two fixes the local backport applied. Debian adds two more upstream changes: [c3b290c](https://github.com/tukaani-project/xz/commit/c3b290c3dc536d16884a6c695618eb08fdbc700a) (the same reinitialization safety for another coder; upstream says it fixes no reachable bug) and a mutex around the threaded decoder's progress counter. |
| Changelog | The package's Debian changelog names GHSA-5qpq-xqfv-j9pg for `+deb13u2` and CVE-2026-34743 for `+deb13u1`. The image test reads the shipped changelog and requires both. |
| Native-library revisions | Only `liblzma5` changes. The donor's `libc6`, `libssl3t64`, `libgcc-s1`, `libstdc++6`, `zlib1g` and `libzstd1` must still equal the distroless base's, as before. `liblzma5` depends only on `libc6`. |
| Behavior | The allocation-failure regression and the Python compatibility cases run against the library the final image loads. |

## Pinned build and provenance

`container/Dockerfile` and `container/liblzma/manifest.json` are the source of
truth for what the build fetches and where it comes from.

- **Snapshots.** `container/liblzma/debian.sources` replaces the donor's package
  sources with dated Debian snapshots only: `debian` `20261006T203214Z`
  (`trixie`, `trixie-updates`) and `debian-security` `20261007T211543Z`
  (`trixie-security`). There is no fallback to a live repository.
- **Authentication.** APT verifies the Debian archive signatures on those
  indexes and the hash of every download against them. `Check-Valid-Until: no`
  applies only because historical snapshots expire by design; signature, TLS
  and hash checks stay on.
- **Exact bytes.** `container/liblzma/verify.py` then requires what the
  manifest records: the three `InRelease` files' SHA-256, the SHA-256 of the
  downloaded `liblzma5` and `liblzma-dev` packages for the build architecture,
  and, for the test tools, the four source files. Any difference fails the
  build. The manifest records the arm64 and amd64 package hashes from the
  signed index; only arm64 has been built and tested.
- **Donor guard.** The build requires the donor to carry exactly
  `5.8.1-1+deb13u1` before installing, and exactly `5.8.1-1+deb13u2` after. A
  donor that changes means this update is reviewed again. It can never replace
  a newer official package with this one.

| Stage | Output / boundary |
| --- | --- |
| `liblzma-official` | The verified official packages under fixed names; nothing built |
| `liblzma-test-build` | The native probe compiled against the official development package, and one fixture extracted from the authenticated upstream source |
| `liblzma-test-tools` | Export-only `/probe` executable and fixture |
| `runtime-files` → `service` | Installs the official package over the donor's, then copies its runtime files, checksums, license and changelog into the final image |

Remove the `liblzma-official` stage and its install step once the donor image
itself carries `5.8.1-1+deb13u2` or later; the test tools then build against
the donor's own development package.

## Tests

```bash
uv run python -m pytest tests/test_liblzma_pin.py tests/test_service_image_runner.py -v
DOCKER_DEFAULT_PLATFORM=linux/arm64 uv run python dev/check_service_images.py --runtime-repo ../sentryruntime
```

`tests/test_liblzma_pin.py` runs offline: the verifier accepts only the
recorded bytes, the build names one version from the pinned snapshots only, and
nothing of the local backport remains.

The service runner builds both services and `liblzma-test-tools`, resolves
their immutable local image IDs, and runs `tests/service_images.py`,
`tests/platform_fit.py` and `tests/liblzma_package.py`. For a TLS-intercepting
build proxy, add `--build-ca-file /path/to/complete-ca-bundle.pem`; never
disable TLS verification. The trust bundle is a build secret, not an image
file.

`tests/liblzma_package.py` has ten cases against the final image:

- **Two native allocation-failure cases** (`alone` and `auto`). A controlled
  allocator rejects allocations of at least 1 MiB: decode a small dictionary,
  reject an 8 MiB dictionary with `LZMA_MEM_ERROR`, then reuse the stream and
  decode successfully. Each requires identical recovered output, an observed
  injected rejection, balanced allocations and frees, and none left. The
  container is network-disabled, read-only, non-root, capability-free, memory
  and PID bounded, with core dumps off; a container OOM is rejected as invalid
  evidence. The probe is mounted read-only for the test and never shipped.
- **Seven Python cases:** raw, XZ and alone round trips, concatenated streams,
  seek and close, incremental decoding, invalid and truncated input, memory
  limits, and explicit decoder reinitialization. These check the wrapper, not
  injected allocation failure.
- **One package case:** the installed version is the pinned one, every file in
  the package's checksum list is present and matches, the license and the
  changelog naming both advisories are shipped, Python has loaded exactly that
  library, and neither test tools nor the old backport's provenance file are
  in the image.

The native cases do not claim direct lzip or MicroLZMA coverage, sanitizer
coverage or exhaustive allocation-failure coverage. Existing evidence is
ARM64; the recorded amd64 hashes are not AMD64 proof.

Passing these resolves one bounded decoder behavior. It is not the release
decision for the image's other findings; see [image security](image-security.md).
No command here publishes an image, deploys a service, changes production or
grants a vulnerability waiver.
