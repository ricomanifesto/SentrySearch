# Exact-image residual risk dispositions

Reviewed October 6, 2026. Assessment only: no scanner suppression, risk waiver,
publication or deployment. Applies to Linux ARM64 local image
`sha256:1acd566a7fd4921aa8305604144d3159467be1d214e69b6ca6a0e80a384df4c0`, built from implementation
`6bd05df31bcaed85535aee6727a024e4a206c74f`. A local image ID is not a registry digest.

## Rebinding at the AWS-05 images (October 8, 2026)

The dispositions below now also cover the AWS-05 local ARM64 images, built from
`aws-04` (`8413f19b6c932f8775cf9ff1490255c641143912`). AWS-05 changed no image
input. Trivy 0.75.0, with the database the accepted scans used (updated
`2026-10-07T07:38:55Z`), reports the same matches as the reviewed and accepted
images, by package, installed version, advisory, severity and fixed version. The
CycloneDX SBOMs list the same components.

| Image | Local index | Raw matches | SBOM components |
| --- | --- | --- | --- |
| Search | `sha256:162ba7e17715f6d90e0487e3e2915301df6c2fc8a80d4cc9bfa66fa2ba2fc997` | 49: C0/H7/M27/L14/U1, unchanged | 82, unchanged |
| Release-tools | `sha256:993b82ff07b991943ae0508675b3a89e1c502867be0e48bfec59bf4b58e3485e` | 54: C0/H1/M23/L30/U0, unchanged | 29, unchanged |
| Runtime | `sha256:343db5c919463eaa49fcc1abc2bdee6ae6c90b508dd654a86f76f6b102548145` | zero | 23; only `golang.org/x/text` v0.40.0 → v0.41.0 (GO-2026-6629) |

**Input delta against the accepted images.** Each image's build context is the
files its `.dockerignore` admits, plus the Dockerfile.

- **Search** (`5fc8f58..aws-04`), 10 files, 767 added lines:
  - `container/Dockerfile` and `container/Dockerfile.dockerignore`: copy the three
    modules below;
  - `dev/migrate_storage.py`: the `--release-job` mode;
  - `dev/prepare_service_volumes.py`: the `runtime-observer` init profile;
  - `release_tools/__init__.py`, `contract.py` and `receipt.py`;
  - `src/storage/database.py`, `release_job.py` and `schema.py`: the release job and
    the shared migration path it reuses.
- **Release-tools:** `release_tools/` only (8 files: the observers, the shared
  contract and the receipt kinds).
- **Runtime** (`bb6e523..aws-03-runtime`): `cmd/migrate/main.go`,
  `cmd/migrate/releasejob.go`, and `go.mod`/`go.sum` (`golang.org/x/text`).

No package, base image or native library changed: the SBOMs list the same
components, apart from the Runtime's `x/text`.

**Recheck.** The A and U rationales that rest on source searches were rechecked over
every added Search line. The rationales cited include CVE-2018-20796,
CVE-2021-45346, CVE-2026-18374, CVE-2026-6368, CVE-2026-6791 and CVE-2026-19499.
No added line calls or imports any of:

- ctypes, cffi or sqlite3;
- wordexp or an iconv/JIS conversion or `ccs=` mode;
- glob, fnmatch, zlib or `crc32_combine`;
- strfmon or locale, tsearch or tdelete;
- resolver or DNS-printing functions, dlopen, or `LD_PRELOAD`;
- subprocess, lzma, tar, zip or gzip;
- the `ssl` module, curses, readline or multiprocessing.

The only matches are SQL text and environment-variable names. The new code
reaches PostgreSQL through the existing psycopg/libpq path. Every disposition below
therefore carries over unchanged as an assessment of these images. None is
accepted, and the 27 retained service and 54 tools matches stay non-additive. The
delta listing and the recheck are saved with the AWS-05 evidence.

A rescan of the same archives with the database updated `2026-10-08T19:05:21Z`
changes two entries, which join this ledger for the release decision:

- Search, 50 matches (C0/H7/M27/L14/U2): `liblzma5 5.8.1-1+deb13u1+sentry1` now
  matches DSA-6549-1, and TEMP-1147318-639065 now names `5.8.1-1+deb13u2` as its
  fix. The official package was by then in `trixie-security`, so the backport
  was due for replacement. That [replacement](liblzma-backport.md) is recorded
  in the next section.
- Release-tools, 55 matches (C0/H1/M24/L30/U0): CVE-2026-107161 (MEDIUM) in
  `libsasl2-2 2.1.28+dfsg1-9`, with no fixed version. It has no disposition yet.

Runtime still reports zero.

### Runtime rebuild with Go 1.26.9 (October 10, 2026)

`govulncheck` began reporting nine standard-library advisories reachable from the
Runtime code in go1.26.6, all fixed in go1.26.9: GO-2026-6603, 6605, 6607, 6608,
6610, 6611, 6612, 6613 and 6617 (`net/http`, `net/textproto`, `crypto/tls`). They
were published after the AWS-05 image was built, and neither database above listed
them. The Runtime was rebuilt from Runtime
`c46533b9666740ea4e11881d978a604196d687ef`, whose only change is the toolchain pin
and the matching `golang:1.26.9-bookworm` builder. The earlier AWS-05 Runtime
image is retained, not removed or retagged, and is superseded.

| Image | Local index | Raw matches | SBOM components |
| --- | --- | --- | --- |
| Runtime (rebuilt) | `sha256:291d4bb328924a3d31addda236937d89f60220005e1856256a3145d28d32785d` | zero | 23; only `stdlib` v1.26.6 → v1.26.9 |

- Source and binary `govulncheck` report no vulnerability for the rebuilt image's
  three binaries; the superseded image's binaries are flagged.
- With the database updated `2026-10-10T12:33:35Z`:
  - the rebuilt Runtime reports zero, where the superseded image now matches 13
    standard-library CVEs per binary;
  - Search is unchanged at 50;
  - release-tools reports 63 (C0/H1/M32/L30/U0). The eight new matches are
    CVE-2026-107708 and CVE-2026-107778 (MEDIUM, no fixed version) in
    `libgssapi-krb5-2`, `libk5crypto3`, `libkrb5-3` and `libkrb5support0`
    `1.21.3-5+deb13u1`. They have no disposition yet and join this ledger for
    the release decision.

### Search and release-tools rebuilt with the official liblzma (October 12, 2026)

Both images were rebuilt from `945106e9b9296c610e22590db4c73d0e9047a243`. The
Runtime image is unchanged. These are local ARM64 identities, not registry
digests, and none is accepted or published.

| Image | Local index | Database `2026-10-07T07:38:55Z` | Database `2026-10-12T13:18:23Z` | SBOM components |
| --- | --- | --- | --- | --- |
| Search | `sha256:5cfa136c70748bad8f6c3539921ca0a6d140154ff42930948243c85e28279f06` | 49: C0/H7/M27/L14/U1 | 48: C0/H7/M27/L14/U0 | 82; only `liblzma5` `5.8.1-1+deb13u1+sentry1` → `5.8.1-1+deb13u2` |
| Release-tools | `sha256:0de498432f802daec067b82fdcfd68f60cdac9279eff472a14746570d514d197` | 54: C0/H1/M23/L30/U0, unchanged | 63: C0/H1/M32/L30/U0, unchanged | 29, unchanged |
| Runtime | `sha256:291d4bb328924a3d31addda236937d89f60220005e1856256a3145d28d32785d` | zero | zero | unchanged |

**Input delta against the previous images** (`8413f19..945106e`, by each
image's `.dockerignore`):

- **Search**, 10 files:
  - `container/Dockerfile` and `container/liblzma/` (`NOTICE`, `debian.sources`,
    `manifest.json`, the new `verify.py`; `recipe.py` and the three patches
    removed): Debian's official `liblzma5 5.8.1-1+deb13u2` replaces the local
    backport ([details](liblzma-backport.md));
  - `src/storage/release_job.py`: the migration job's stop and deadline bounds
    no longer wait for the statement's cancellation.
- **Release-tools**, 1 file: `release_tools/observe.py`, the observer's
  whole-check deadline.

**What changed in the matches.**

- With the older database, Search's 49 tuples are the same except that the
  liblzma row now names `5.8.1-1+deb13u2`: that database predates Debian's fix,
  so it still lists `TEMP-1147318-639065` with no fixed version.
- With the database of October 12, both liblzma rows are gone (DSA-6549-1 and
  `TEMP-1147318-639065`, each fixed in `5.8.1-1+deb13u2`). Nothing was added.
  Search has no UNKNOWN match left.
- Release-tools is the same 63 as on October 10: `libsasl2-2` CVE-2026-107161
  and the four krb5 libraries' CVE-2026-107708 and CVE-2026-107778 (MEDIUM, no
  fixed version) still have no disposition.

**Recheck.** The 93 added Python lines in those two files import only
`threading` and `time`. None calls or imports anything the A and U rationales
rest on (the list under the October 8 rebinding). Every other disposition
therefore carries over unchanged as an assessment of these images. None is
accepted, and the 27 retained service and 54 tools matches stay non-additive.

### Fresh scan of the same images (October 17, 2026)

No image was rebuilt. The three local identities above were scanned again from
their archives (each archive's SHA-256 checked against its recorded binding)
with Trivy 0.75.0 and a database freshly downloaded from
`mirror.gcr.io/aquasec/trivy-db:2`, updated `2026-10-16T01:13:54Z`. syft is not
installed on the scanning host; the SBOMs are Trivy's CycloneDX, as before. No
severity filter, ignore-unfixed setting or suppression was used.

| Image | Raw matches | Against the database of October 12 |
| --- | --- | --- |
| Search | 48: C0/H7/M27/L14/U0 | the same 48 tuples |
| Release-tools | 63: C0/H1/M32/L30/U0 | the same 63 tuples; Trivy now reports CVE-2026-107161 `fix_deferred` (was `affected`) |
| Runtime | zero | zero |

**Recommended dispositions for the nine release-tools matches that joined after
October 7.** These are recommendations for the release owner; none is accepted
here. They are not the whole of release-tools' open matches. Of the other 54,
33 share the Search ledger's advisories and stay unaccepted for this image, and
21 LOW matches of nine advisories from `psql`'s Kerberos and OpenLDAP
dependencies ([image security](image-security.md)) still need their
tools-specific review: `libldap2` CVE-2015-3276, CVE-2017-14159, CVE-2017-17740,
CVE-2020-15719 and CVE-2026-22185, and the four krb5 libraries' CVE-2018-5709,
CVE-2024-26458, CVE-2024-26461 and CVE-2026-11850.

Evidence, read from the image's archive without running it (the ELF dynamic
dependencies of all 360 ELF files): `release_tools` reaches PostgreSQL only by
running `psql` (`release_tools/session.py`), in a constructed environment with
`PGSSLMODE=verify-full`, `PGGSSENCMODE=disable` and
`PGREQUIREAUTH=scram-sha-256`, and with no `PGSERVICE`, `PGSERVICEFILE` or
`PGSYSCONFDIR`. The image's libpq consumers are `psql` and PostgreSQL's
`isolationtester` (retained from the client package, never run; also a client).
Only libpq links `libgssapi_krb5`; `libkrb5` is linked only by `libgssapi_krb5`
and the SPAKE preauthentication plugin; only `libldap` links `libsasl2`. Python's
native `_ctypes` extension is absent, so `ctypes` cannot load a library. There is no SASL mechanism plugin, Kerberos
KDC, keytab, `krb5.conf`, `ldap.conf` or `pg_service.conf`.

| Advisory | Matched packages | Recommended | Reason and reopening condition |
| --- | --- | --- | --- |
| [CVE-2026-107161](https://security-tracker.debian.org/tracker/CVE-2026-107161) / MEDIUM (Red Hat: Moderate, CVSS 3.1 7.5) | `libsasl2-2=2.1.28+dfsg1-9` | **N** | The overflow is in the DIGEST-MD5 mechanism plugin. Debian ships mechanism plugins in `libsasl2-modules`, which the image does not contain: there is no plugin directory, and `libsasl2.so.2` itself has no DIGEST-MD5 code. libsasl2 is reached only through libldap, which libpq uses only for an LDAP service lookup, which needs a service name the environment never sets. Reopens if a mechanism plugin, `SASL_PATH`, a service file or a service variable is added. Debian marks trixie `<no-dsa>` ("Will be fixed via point release"); sid is fixed in `2.1.28+dfsg1-12`. |
| [CVE-2026-107708](https://security-tracker.debian.org/tracker/CVE-2026-107708) / MEDIUM | `libgssapi-krb5-2`, `libk5crypto3`, `libkrb5-3`, `libkrb5support0` `=1.21.3-5+deb13u1` | **N** | The faulty function is in the KDC (`src/kdc/kdc_util.c`), which builds `krb5kdc` only; the image carries the client libraries and no KDC. Reopens if a KDC is added. |
| [CVE-2026-107778](https://security-tracker.debian.org/tracker/CVE-2026-107778) / MEDIUM | the same four packages | **A**, caller boundary established | `krb5_rd_cred` (`rd_cred.c`) is part of `libkrb5`, so the code is retained. It is reached by a GSS acceptor through `gss_accept_sec_context()`, or by a direct caller of that public function. libpq only ever initiates GSS exchanges (it imports `gss_init_sec_context`, not `gss_accept_sec_context`), and under `PGGSSENCMODE=disable` and `PGREQUIREAUTH=scram-sha-256` it starts none: it refuses a GSS authentication request before starting the exchange, and never probes for a credential cache. Nothing else in the image links `libkrb5` or `libgssapi_krb5` but the SPAKE plugin, which libkrb5 loads only for Kerberos preauthentication. Reopens if `psql`'s environment changes, or a keytab, `krb5.conf`, GSS acceptor or any new consumer of `libkrb5` or `libgssapi_krb5` is added. |

These recommendations do not change the counts above: the 27 retained Search
matches and the release-tools matches stay non-additive and unaccepted until
the release owner decides.

## Result and scope

The retained Trivy 0.75.0 report (database updated `2026-10-06T19:11:49Z`)
contains **49 package/advisory matches across 39 advisories**:
C0/H7/M27/L14/U1. Raw findings are unchanged; no fresh scan or rebuild was needed
for this source/component review. Refresh the exact intended release image before
any later release decision. Zero Python findings is not a native-code safety claim.

| Disposition | Package/advisory matches | Meaning |
| --- | ---: | --- |
| N — narrowly not affected | 21 | Named affected component absent, different architecture, or exact build/source excludes the faulty branch. Not a package-family exemption. |
| F — fixed | 1 | liblzma: first by a local backport, and since October 12, 2026 by Debian's official `5.8.1-1+deb13u2`, with the same bounded behavioral proof. A scanner database older than the fix still lists the raw UNKNOWN/upstream HIGH match. |
| A — affected code retained | 16 | Source/build evidence supports applicability; no remote Search exploit demonstrated. |
| U — unresolved applicability / disputed | 11 | Caller, native-template, privilege or disputed threat-model boundary is not established. Keep release hold. |

All seven scanner-HIGH matches concern absent mount/libmount, nsenter or infocmp
components. This does **not** mean every remaining risk is below HIGH: liblzma's
upstream rating is HIGH, and glibc CVE-2026-19499 is rated 7.7 in its upstream
advisory despite the scanner's MEDIUM label. Preserve both classifications.

GCC PBDS has three package-only N entries and one U entry: missing headers and
no matching strings among 414 ELF files do not exclude inlined native-wheel
instantiations. The whole-image advisory remains unresolved. Similarly, three
ncurses parser matches represent one retained affected parser, not three separate
exploit paths. Counts are accounting, not independent vulnerability counts.

## Evidence method and limits

Review used Debian/upstream advisories and exact source/build content, bounded
network-disabled/read-only/capability-dropped image inspection, installed package
checksums, exported symbols and targeted disassembly. No untrusted exploit,
real-provider request, new package build or application-suite rerun was performed.
Sourceware reads were partly rate-limited; Debian primary records covered every
native-core advisory. Missing repository calls or command-line tools alone never
establish absence of a retained library path.

Important corrections:

- **ncurses:** `libtic.so.6.5` is shipped by `libtinfo6`; its parser remains
  affected even though `tic`/`infocmp` and some parser exports are absent.
- **SQLite:** `ENABLE_SESSION`, `apply_v2`, concat and changegroup exist. The
  apply-v3-named advisory fixes shared older code; absent `apply_v3` is not clearance.
- **zlib:** exact 1.3.1 source predates `gz_vacate`, but retains the independent
  negative-length CRC-combine loop. Upgrading blindly to 1.3.2 does not solve both.
- **libstdc++:** exact aligned-new implementation uses `posix_memalign` with
  unrounded size; this proves the relevant build exclusion, not PBDS safety.
- **libc:** retained converters, formatting, tree, resolver and word-expansion
  functions remain open. Disputed advisories and absent SUID files are not fixes.

## Complete advisory-to-package ledger

Every raw match appears under its exact advisory and installed package below.
The linked source plus rationale owns the disposition. All decisions expire on
an image/build/architecture/input/privilege/mount change and must be rechecked
before release; narrower invalidation conditions follow the ledger.

| Advisory / scanner severity | Matched packages and disposition | Evidence / remaining boundary |
| --- | --- | --- |
| [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756) / LOW | `libc6=2.41-12+deb13u4` **U** | glibc glob can consume unbounded resources; Debian assigns caller responsibility, not a patched version. glob symbol present. Search is not an FTP daemon; no full native glob caller/input bound proof. |
| [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) / LOW | `libc6=2.41-12+deb13u4` **U** | POSIX regex recursive matching resource use; upstream treats as security exception. regexec present; no explicit repository native regex calls. Python re and missing grep do not prove libc regex consumers absent. |
| [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) / LOW | `libc6=2.41-12+deb13u4` **U** | NPTL stack-guard bypass report; upstream classifies non-security and requires a separate overflow. libc/pthread_create present. No local patch or exhaustive safety proof. |
| [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) / LOW | `libc6=2.41-12+deb13u4` **U** | Malicious ELF/loader tracing report described via ldd; upstream non-security classification. ldd absent, loader present. Absence of wrapper does not exclude equivalent loader tracing/dlopen behavior. |
| [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024) / LOW | `libc6=2.41-12+deb13u4` **U** | Thread-stack/heap caching ASLR bypass report; upstream non-security classification. Threading and libc remain; no fixed package or architecture exclusion established. |
| [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025) / LOW | `libc6=2.41-12+deb13u4` **U** | Predictability of pthread-created thread heap addresses; upstream says ASLR bypass alone is not vulnerability. pthread_create present; no exclusion of underlying caching/address behavior. |
| [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) / LOW | `libc6=2.41-12+deb13u4` **U** | Distinct crafted POSIX regex recursion case, disputed by upstream. regexec present; native consumer reachability unresolved. |
| [CVE-2021-45346](https://security-tracker.debian.org/tracker/CVE-2021-45346) / LOW | `libsqlite3-0=3.46.1-7+deb13u2` **U** | Retained SQLite supports the disputed corrupt-database behavior; neither a local fix nor affected-code absence is established. Exact image contains SQLite3.46.1. Maintainer describes overlapping database records after attacker file corruption, not arbitrary process-memory disclosure. Application persistence configuration constructs postgresql+psycopg; no direct production SQLite import/caller found in the bounded source search. This does not prove every transitive caller absent. |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) / LOW | `libuuid1=2.41.5-0+deb13u1` **N** | Affected util-linux chfn/chsh implementation is neither built in Debian nor present in this image. Debian tracker records --disable-chfn-chsh for util-linux, with those commands supplied by a different source package when installed. Full image walk finds neither chfn nor chsh. |
| [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) / LOW | `libncursesw6=6.5+20250216-2` **A**; `libtinfo6=6.5+20250216-2` **A**; `ncurses-base=6.5+20250216-2` **A** | The affected parser remains in libtic delivered by libtinfo6, despite absent tic and infocmp executables. libtic.so.6.5 is present and its MD5 matches libtinfo6 package metadata. _nc_read_entry_source is exported by libtic; Debian comp_parse.c calls _nc_parse_entry, which calls postprocess_termcap. Debian build uses a separate ticlib; checking parser exports on libtinfo/libncursesw alone would be a false negative. The exact source precedes the 2025-03-29 bounds fix; source-package patch series contains only three unrelated Debian adjustments. |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) / HIGH | `libncursesw6=6.5+20250216-2` **N**; `libtinfo6=6.5+20250216-2` **N**; `ncurses-base=6.5+20250216-2` **N** | Affected infocmp analyze_string command component absent. Full image walk finds no infocmp. Retained ncurses libraries and terminfo data are source-package matches, not the progs/infocmp.c program. |
| [CVE-2025-70873](https://security-tracker.debian.org/tracker/CVE-2025-70873) / LOW | `libsqlite3-0=3.46.1-7+deb13u2` **N** | Affected SQLite zipfile extension is not part of this Debian build/image. Debian tracker explicitly says the extension is not built in its binary packages. Exact image lacks zipfile extension shared objects, sqlite3_zipfile_init export, and zipfile in the in-memory SQLite module list. Python's unrelated standard-library zipfile module is not this SQLite extension. |
| [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) / MEDIUM | `gcc-14-base=14.2.0-19` **N**; `libgcc-s1=14.2.0-19` **N**; `libgomp1=14.2.0-19` **N**; `libstdc++6=14.2.0-19` **U** | PBDS binary_heap erase_if template leaves dangling storage after reallocation; fixed source is header erase_fn_imps.hpp. No affected header or PBDS/binary_heap strings found among414 ELF files. That does not exclude optimized/inlined template instances in native wheels. Runtime gcc-base/libgcc/libgomp payloads are distinct from C++ template source. |
| [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | Attacker-controlled effectively empty fopen ,ccs= extension can overflow; upstream through2.45 affected. libc2.41-12+deb13u4 and fopen present. Repository scan found no explicit fopen/ctypes caller; this is not complete native dependency call-graph proof. |
| [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | strfmon/strfmon_l right-justification buffer handling in2.38–2.44. Both functions present in retained libc2.41. Upstream advisory rates7.7 despite scanner MEDIUM; no Search caller established. |
| [CVE-2026-19542](https://security-tracker.debian.org/tracker/CVE-2026-19542) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | tdelete stack capacity boundary on deep tsearch trees; versions2.1–2.44. tdelete present in libc2.41. Required large/deep tree and native caller not demonstrated; memory caps do not establish absence. |
| [CVE-2026-27171](https://security-tracker.debian.org/tracker/CVE-2026-27171) / MEDIUM | `zlib1g=1:1.3.dfsg+really1.3.1-1+b1` **A** | crc32_combine64/combine_gen64 negative-length arithmetic-shift loop before1.3.2. Exact zlib1.3.1 exports both functions; disassembly has arithmetic right shifts at0x3a14/0x3a5c and loop. Python3.11 zlib lacks crc32_combine, but native/ctypes access remains possible. |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) / MEDIUM | `libuuid1=2.41.5-0+deb13u1` **N** | Affected login executable/PAM_RHOST canonicalization component is absent. Full image walk finds no login binary; retained libuuid is not login. |
| [CVE-2026-42250](https://security-tracker.debian.org/tracker/CVE-2026-42250) / MEDIUM | `libbz2-1.0=1.0.8-6` **N** | Affected bzip2recover component absent; libbz2 is not the recovery executable. Full image walk finds no bzip2recover. libbz2.so.1.0.4 is present and matches its package manifest. Upstream fix changes only bzip2recover.c. |
| [CVE-2026-50812](https://security-tracker.debian.org/tracker/CVE-2026-50812) / MEDIUM | `libsqlite3-0=3.46.1-7+deb13u2` **A** | The shared Session apply implementation still has the pre-fix null-guard condition; missing apply_v3 does not exclude older apply_v2. Exact image reports SQLite 3.46.1 and ENABLE_SESSION; apply_v2 is exported, apply_v3 is not. Upstream Fossil e807d4e379 maps to GitHub b869ed6 and changes sessionApplyOneOp; its regression invokes apply_v2. Exact Debian source retains the pre-fix condition at line 4921; this is source and feature evidence, not an executed exploit. |
| [CVE-2026-50813](https://security-tracker.debian.org/tracker/CVE-2026-50813) / MEDIUM | `libsqlite3-0=3.46.1-7+deb13u2` **A** | Session changeset concat/changegroup code and pre-fix varint behavior remain present. Exact image enables Session and exports sqlite3changeset_concat and sqlite3changegroup_add. Exact Debian source sessionVarintGet lacks the high-bit mask introduced by the upstream fix. Upstream Fossil 869a51ae84df maps to GitHub c597ed7 and fixes Session buffer overread. |
| [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | Deprecated DNS-printing functions fail supplied buffer bounds for TSIG. libresolv retained and __fp_nquery present. Unversioned ns_printrr/ns_printrrf lookup fails, which does not prove compatibility symbols/internal code absent. Ordinary DNS resolution is not this debug path. |
| [CVE-2026-6238](https://security-tracker.debian.org/tracker/CVE-2026-6238) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | Deprecated DNS-printing routines fail RDATA bounds for certain records;2.0.1–2.43. Same retained libresolv/__fp_nquery evidence. Upstream explicitly distinguishes these from normal resolver execution. |
| [CVE-2026-6368](https://security-tracker.debian.org/tracker/CVE-2026-6368) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | wordexp WRDE_APPEND may leave invalid we_wordv for subsequent wordfree;2.0–2.43. wordexp present. Absence of shell/tools and absent repository wordexp call are not proof against all native callers. |
| [CVE-2026-6791](https://security-tracker.debian.org/tracker/CVE-2026-6791) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | Unbounded tilde username stack allocation through wordexp. wordexp present in libc2.41; no explicit app call found. Python path expansion cannot clear unrelated native consumers. |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) / HIGH | `libuuid1=2.41.5-0+deb13u1` **N** | Affected mount/libmount external-helper post-hooks component is absent; matched libuuid does not contain that implementation. Full image walk finds no mount, nsenter or libmount payload. Package inventory retains libuuid1 but not libmount1/mount/util-linux; zero setid regular files found. This is component absence, not reliance on capability dropping alone. |
| [CVE-2026-77117](https://security-tracker.debian.org/tracker/CVE-2026-77117) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | SHIFT_JISX0213 converter retains pending codepoint and can fail to progress. /usr/lib/aarch64-linux-gnu/gconv/SHIFT_JISX0213.so present. Python codecs do not prove native iconv paths absent. |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) / HIGH | `libuuid1=2.41.5-0+deb13u1` **N** | Affected nsenter --join-cgroup inherited descriptor component is absent; matched libuuid does not contain that implementation. Full image walk finds no mount, nsenter or libmount payload. Package inventory retains libuuid1 but not libmount1/mount/util-linux; zero setid regular files found. This is component absence, not reliance on capability dropping alone. |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) / HIGH | `libuuid1=2.41.5-0+deb13u1` **N** | Affected mount/libmount X-mount.subdir resolution component is absent; matched libuuid does not contain that implementation. Full image walk finds no mount, nsenter or libmount payload. Package inventory retains libuuid1 but not libmount1/mount/util-linux; zero setid regular files found. This is component absence, not reliance on capability dropping alone. |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) / HIGH | `libuuid1=2.41.5-0+deb13u1` **N** | Affected mount/libmount restricted bind-mount source handling component is absent; matched libuuid does not contain that implementation. Full image walk finds no mount, nsenter or libmount payload. Package inventory retains libuuid1 but not libmount1/mount/util-linux; zero setid regular files found. This is component absence, not reliance on capability dropping alone. |
| [CVE-2026-80489](https://security-tracker.debian.org/tracker/CVE-2026-80489) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | EUC_JISX0213 pending-codepoint converter non-progress, distinct from SHIFT_JISX0213. /usr/lib/aarch64-linux-gnu/gconv/EUC-JISX0213.so present. No adversarial conversion executed. |
| [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) / MEDIUM | `zlib1g=1:1.3.dfsg+really1.3.1-1+b1` **N** | gz_vacate nonblocking-write support was introduced in1.3.1.2; report range is1.3.1.2–1.3.2. Installed/runtime zlib1.3.1; exact Debian source gzwrite.c lacks gz_vacate and its patch series is empty. Source SHA256469b1e58932ea11bdda2a153f6655f7b3c13254240fae157181b49ed1bc93b47. Installed libz checksum matches package inventory. |
| [CVE-2026-8674](https://security-tracker.debian.org/tracker/CVE-2026-8674) / MEDIUM | `libc6=2.41-12+deb13u4` **A** | Resolver initializes from roughly200-character search domain and can abort;2.26–2.44. getaddrinfo present; local inspection had no search directive and LOCALDOMAIN unset. Docker-generated local resolv.conf is not AWS staging configuration evidence. |
| [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805) / MEDIUM | `libc6=2.41-12+deb13u4` **U** | AT_SECURE loader ORIGIN/parent traversal race;2.14–2.44, privileged executable and filesystem conditions required. Loader present; existing image payload walk found no SUID/SGID or file capabilities. No runtime privileged executable trigger established. Host sysctl/mount/AT_SECURE conditions not verified for future platform. |
| [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092) / MEDIUM | `libc6=2.41-12+deb13u4` **N** | Overflow is in enabled nscd daemon, not general libc DNS caller. nscd executable absent across existing /usr,/app,/bin,/sbin,/lib payload roots; nscd socket absent. Retained libc is source-family match. |
| [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) / MEDIUM | `gcc-14-base=14.2.0-19` **N**; `libgcc-s1=14.2.0-19` **N**; `libgomp1=14.2.0-19` **N**; `libstdc++6=14.2.0-19` **N** | Unsafe rounding occurs only in certain aligned-new allocation fallbacks, not POSIX posix_memalign branch. Exact libstdc++.so.6.0.33 SHA256fff1f0050a33ddf29c44634c7639ac16e2573a61e3daab4fcc4c007b432ccf19: disassembly of _ZnwmSt11align_val_t at0xaa218 calls posix_memalign with unrounded size. Upstream fix explicitly excludes this branch. |
| [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818) / MEDIUM | `libc6=2.41-12+deb13u4` **U** | AT_SECURE loader ORIGIN RPATH/RUNPATH buffer handling;2.14–2.44. Loader present; no privileged payload files found. Exact role privilege/mount contract is still a deployment-planning boundary. |
| [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399) / LOW | `libc6=2.41-12+deb13u4` **N** | Overread confined to Power8-optimized strncasecmp. Exact immutable image and installed libc are ARM64/aarch64; Power8 implementation is not this architecture. |
| [TEMP-1147318-639065](https://github.com/tukaani-project/xz/security/advisories/GHSA-5qpq-xqfv-j9pg) / UNKNOWN | `liblzma5=5.8.1-1+deb13u2` **F** | Fixed by Debian's official package (DSA-6549-1) since October 12, 2026; before that by the repository-owned backport `5.8.1-1+deb13u1+sentry1`. The official package cherry-picks upstream fe4d763 and e5e63d5, with changed lines identical to the backport's, and its changelog names the advisory. Pinned by dated snapshot, Release hashes and package SHA-256. Controlled alone/auto allocation-failure reuse and seven Python compatibility checks pass against the library the image loads. No direct lzip/MicroLZMA fault injection, sanitizer, AMD64 or cloud proof. |

## Release disposition and finite next action

The 27 A/U matches remain a release hold, not a mandate to keep doing broad
minimization. The maintainer/release owner must choose compatible supported fixes,
more specific source/caller proof, or an explicit time-bounded environment-specific
risk acceptance. No such acceptance is granted here. Source-package disputes are
recorded rather than silently relabeled safe. Updating runtime libstdc++ does not
repair an already compiled vulnerable header template.

For any later synthetic-staging proposal, require exact image/architecture and
role coverage (including the root Search initializer in Runtime tasks), closed
fixture inputs, no arbitrary SQLite/changeset/termcap/ELF/plugin intake, enforced
resource/privilege/mount/network boundaries, actual resolver configuration review,
a named owner and expiry. These controls reduce exposure; they are not patches
or complete transitive reachability proof. Fargate does not support Docker's
`no-new-privileges` setting through `dockerSecurityOptions`; do not treat a local
test flag as an enforced cloud control.

The source review does not certify future mounted libraries, debug images,
sidecars, nscd sockets, alternate allocators, native plugins, expanded encodings,
static native-wheel templates or new input paths. Any such change reopens the
associated dispositions. No production/customer-data exception follows from a
synthetic-staging decision.

The [liblzma replacement](liblzma-backport.md) was carried out on October 12,
2026: the authenticated official fixed Trixie package, the behavioral and native
compatibility cases, the service suites and fresh scans on ARM64, with the
temporary recipe removed and the behavioral tests retained. No direct
lzip/MicroLZMA fault injection, sanitizer or AMD64 proof is claimed.

## Additional primary implementation references

- [Source 1](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0015)
- [Source 2](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0017)
- [Source 3](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0018)
- [Source 4](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0011)
- [Source 5](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0012)
- [Source 6](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0014)
- [Source 7](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0013)
- [Source 8](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0019)
- [Source 9](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0020)
- [Source 10](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0021)
- [Source 11](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0022)
- [Source 12](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0023)
- [Source 13](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0016)
- [Source 14](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0024)
- [Source 15](https://github.com/gcc-mirror/gcc/commit/aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6)
- [Source 16](https://github.com/gcc-mirror/gcc/commit/59d235ffa5a69231eb42e5290d52dc8c90d28b7a)
- [Source 17](https://github.com/madler/zlib/commit/ba829a458576d1ff0f26fc7230c6de816d1f6a77)
- [Source 18](https://sources.debian.org/src/zlib/1:1.3.dfsg%2Breally1.3.1-1/crc32.c/)
- [Source 19](https://github.com/madler/zlib/commit/81cc0bebedd935daeb81b0b6e475d8786b51af3d)
- [Source 20](https://sources.debian.org/src/zlib/1:1.3.dfsg%2Breally1.3.1-1/gzwrite.c/)
- [Source 21](https://sources.debian.org/data/main/z/zlib/1%3A1.3.dfsg%2Breally1.3.1-1/debian/patches/series)
- [Source 22](https://sourceware.org/cgit/bzip2/commit/?id=35d122a3df8b0cc4082a4d89fdc6ee99f375fe67)
- [Source 23](https://invisible-island.net/ncurses/NEWS.html#index-t20251213)
- [Source 24](https://invisible-island.net/ncurses/NEWS.html#index-t20250329)
- [Source 25](https://sources.debian.org/src/ncurses/6.5%2B20250216-2/debian/rules/)
- [Source 26](https://sources.debian.org/data/main/n/ncurses/6.5%2B20250216-2/ncurses/modules)
- [Source 27](https://sources.debian.org/data/main/n/ncurses/6.5%2B20250216-2/ncurses/tinfo/comp_parse.c)
- [Source 28](https://sources.debian.org/data/main/n/ncurses/6.5%2B20250216-2/ncurses/tinfo/parse_entry.c)
- [Source 29](https://sources.debian.org/data/main/n/ncurses/6.5%2B20250216-2/debian/patches/series)
- [Source 30](https://sqlite.org/src/info/e807d4e3798efd53)
- [Source 31](https://github.com/sqlite/sqlite/commit/b869ed6b067d623cb1383549f2a18aa35508385d)
- [Source 32](https://sources.debian.org/data/main/s/sqlite3/3.46.1-7%2Bdeb13u2/ext/session/sqlite3session.c)
- [Source 33](https://sources.debian.org/data/main/s/sqlite3/3.46.1-7%2Bdeb13u2/debian/patches/series)
- [Source 34](https://sqlite.org/src/info/869a51ae84df)
- [Source 35](https://github.com/sqlite/sqlite/commit/c597ed79d1bd03f57198d10d1f431adda293cf2e)
- [Source 36](https://sqlite.org/forum/forumpost/056d557c2f8c452ed5bb9c215414c802b215ce437be82be047726e521342161e)
- [Source 37](https://sqlite.org/src/info/3d459f1fb1bd1b5e)
- [Source 38](https://github.com/util-linux/util-linux/security/advisories/GHSA-m25x-3hj9-m26f)
- [Source 39](https://github.com/util-linux/util-linux/security/advisories/GHSA-55fx-f4gg-cfhj)
- [Source 40](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv)
- [Source 41](https://github.com/util-linux/util-linux/security/advisories/GHSA-rh77-686x-2f2m)
- [Source 42](https://github.com/util-linux/util-linux/commit/8b29aeb081e297e48c4c1ac53d88ae07e1331984)
- [Source 43](https://github.com/util-linux/util-linux/commit/faa5a3a83ad0cb5e2c303edbfd8cd823c9d94c17)
- [Source 44](https://security-tracker.debian.org/tracker/TEMP-1147318-639065)
