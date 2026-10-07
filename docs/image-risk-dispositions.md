# Exact-image residual risk dispositions

Reviewed October 6, 2026. Assessment only: no scanner suppression, risk waiver,
publication or deployment. Applies to Linux ARM64 local image
`sha256:1acd566a7fd4921aa8305604144d3159467be1d214e69b6ca6a0e80a384df4c0`, built from implementation
`6bd05df31bcaed85535aee6727a024e4a206c74f`. A local image ID is not a registry digest.

## Result and scope

The retained Trivy 0.75.0 report (database updated `2026-10-06T19:11:49Z`)
contains **49 package/advisory matches across 39 advisories**:
C0/H7/M27/L14/U1. Raw findings are unchanged; no fresh scan or rebuild was needed
for this source/component review. Refresh the exact intended release image before
any later release decision. Zero Python findings is not a native-code safety claim.

| Disposition | Package/advisory matches | Meaning |
| --- | ---: | --- |
| N — narrowly not affected | 21 | Named affected component absent, different architecture, or exact build/source excludes the faulty branch. Not a package-family exemption. |
| F — fixed by local backport | 1 | Pinned liblzma source and bounded behavioral proof; raw UNKNOWN/upstream HIGH match retained. |
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
| [TEMP-1147318-639065](https://github.com/tukaani-project/xz/security/advisories/GHSA-5qpq-xqfv-j9pg) / UNKNOWN | `liblzma5=5.8.1-1+deb13u1+sentry1` **F** | Two upstream decoder reinitialization/cleanup fixes retained in the repository-owned Debian backport. Pinned fe4d763 + e5e63d5; regression ff834f2. Same library bytes as independently reviewed ABI candidate. Controlled alone/auto allocation-failure reuse red/green; seven Python compatibility checks; final 30 container and 737 setup checks. Source/package checksums and two identical clean packages recorded in adoption receipt. No direct lzip/MicroLZMA fault injection, sanitizer, AMD64 or cloud proof. |

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

The [liblzma replacement procedure](liblzma-backport.md) remains mandatory:
authenticated official fixed Trixie source, behavioral/native compatibility,
service lifecycle and fresh scan gates on intended architectures, then remove
the temporary recipe but retain behavioral tests. No direct lzip/MicroLZMA fault
injection, sanitizer or AMD64 proof is claimed.

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
