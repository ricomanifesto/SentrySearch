"""The operator's session credentials: one explicit, owner-only file and nothing else.

The CLI never resolves ambient credentials (environment, profiles, config files,
instance or container metadata, web identity). The credential custodian writes a
short-lived session to a regular file that only the operator can read (mode
0400), outside any repository, with no symlink anywhere in its path and no
group- or world-writable parent, and on macOS no extended ACL entry that allows
anything on the file or a parent. The file is opened once, without following
links, and every check after that uses the same descriptor.

Nothing in the file is authenticated identity. ``expires_at`` is the custodian's
statement of the session lifetime (``GetCallerIdentity`` reports none) and
``session_name`` must merely agree with the manifest operator; the account and
assumed-role session are proven separately by the preflight. Key prefixes and a
token's presence prove neither identity nor validity: a long-lived ``AKIA`` key
or a missing token is refused, but their absence proves nothing.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCHEMA = "sentry.operator-session.v1"
FIELDS = frozenset(
    {"schema", "access_key_id", "secret_access_key", "session_token", "expires_at", "session_name"}
)
MAX_FILE_BYTES = 8192
REQUIRED_MARGIN = timedelta(minutes=10)
# The longest STS session lifetime (federation/session tokens); anything later is not a
# short-lived session and is refused rather than trusted.
MAX_SESSION_LIFETIME = timedelta(hours=36)
_TEMPORARY_KEY = re.compile(r"ASIA[A-Z0-9]{16}")
_SECRET = re.compile(r"[A-Za-z0-9/+]{40}")
_TOKEN = re.compile(r"[A-Za-z0-9/+=]{16,4096}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
# IAM role-session names.
SESSION_NAME = re.compile(r"[\w+=,.@-]{2,64}")


class CredentialsRefused(Exception):
    """The file cannot be used; the reason never contains a credential value."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SessionCredentials:
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    expires_at: datetime
    session_name: str


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CredentialsRefused("credentials_malformed")
        result[key] = value
    return result


def _no_float(_text: str) -> None:
    raise CredentialsRefused("credentials_malformed")


_ACL_TYPE_EXTENDED = 0x00000100  # macOS <sys/acl.h>


def _libc():
    library = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    library.acl_get_fd_np.restype = ctypes.c_void_p
    library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    library.acl_get_link_np.restype = ctypes.c_void_p
    library.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    library.acl_to_text.restype = ctypes.c_void_p
    library.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    library.acl_free.argtypes = [ctypes.c_void_p]
    return library


def _acl_grants_anything(*, descriptor: int | None = None, path: Path | None = None) -> bool:
    """True if a macOS extended ACL has any allow entry; unverifiable is refused.

    Mode bits alone do not show macOS ACLs: an ``allow`` entry can let anyone
    read a 0400 file or replace entries in a 0700 directory. ``deny`` entries
    only restrict (macOS gives home folders ``everyone deny delete``) and pass.
    Elsewhere POSIX ACLs widen the group mode bits, which the mode checks refuse.
    """
    if sys.platform != "darwin":
        return False
    library = _libc()
    if descriptor is not None:
        acl = library.acl_get_fd_np(descriptor, _ACL_TYPE_EXTENDED)
    else:
        acl = library.acl_get_link_np(os.fsencode(str(path)), _ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return False
        raise CredentialsRefused("credentials_path_unsafe")
    try:
        length = ctypes.c_ssize_t()
        text = library.acl_to_text(acl, ctypes.byref(length))
        if not text:
            raise CredentialsRefused("credentials_path_unsafe")
        try:
            entries = ctypes.string_at(text, length.value).decode("utf-8", "replace").splitlines()
        finally:
            library.acl_free(text)
    finally:
        library.acl_free(acl)
    for entry in entries:
        if not entry or entry.startswith("!#acl"):
            continue
        fields = entry.split(":")
        if len(fields) < 3 or fields[-2] != "deny":
            return True
    return False


def _check_path(path: Path, euid: int) -> None:
    """Absolute, symlink-free, outside any repository, under owner- or root-held directories."""
    if not path.is_absolute() or os.path.realpath(path) != str(path):
        raise CredentialsRefused("credentials_path_unsafe")
    for parent in path.parents:
        try:
            info = os.lstat(parent)
        except OSError:
            raise CredentialsRefused("credentials_path_unsafe") from None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, euid):
            raise CredentialsRefused("credentials_path_unsafe")
        writable_by_others = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        # A root-owned sticky directory (such as /private/tmp) cannot have our
        # entries renamed or removed by others; anything else writable is unsafe.
        if writable_by_others and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise CredentialsRefused("credentials_path_unsafe")
        if os.path.lexists(parent / ".git"):
            raise CredentialsRefused("credentials_in_repository")
        if _acl_grants_anything(path=parent):
            raise CredentialsRefused("credentials_path_unsafe")


def _read_once(path: Path, euid: int) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise CredentialsRefused("credentials_unreadable") from None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != euid
            or stat.S_IMODE(info.st_mode) != 0o400
            or info.st_nlink != 1
            or not 0 < info.st_size <= MAX_FILE_BYTES
            or _acl_grants_anything(descriptor=descriptor)
        ):
            raise CredentialsRefused("credentials_file_unsafe")
        data = os.read(descriptor, MAX_FILE_BYTES + 1)
    except OSError:
        raise CredentialsRefused("credentials_unreadable") from None
    finally:
        os.close(descriptor)
    if len(data) != info.st_size:
        raise CredentialsRefused("credentials_file_unsafe")
    return data


def _parse(data: bytes) -> dict[str, object]:
    document: object = None
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_no_float,
            parse_constant=_no_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        pass
    # Raised outside the handler: a JSON error can quote the file's content.
    if not isinstance(document, dict) or set(document) != FIELDS:
        raise CredentialsRefused("credentials_malformed")
    if document["schema"] != SCHEMA or not all(isinstance(v, str) for v in document.values()):
        raise CredentialsRefused("credentials_malformed")
    return document


def load_session_credentials(
    path: str | Path,
    *,
    operator: str,
    now: datetime,
    required_until: datetime,
    euid: Callable[[], int] = os.geteuid,
) -> SessionCredentials:
    """Read and check the custodian's session file for this operator and window."""
    target = Path(path)
    user = euid()
    _check_path(target, user)
    document = _parse(_read_once(target, user))
    key = str(document["access_key_id"])
    if key.startswith("AKIA"):
        raise CredentialsRefused("long_lived_key_refused")
    if not _TEMPORARY_KEY.fullmatch(key):
        raise CredentialsRefused("credentials_malformed")
    if not _SECRET.fullmatch(str(document["secret_access_key"])):
        raise CredentialsRefused("credentials_malformed")
    if not _TOKEN.fullmatch(str(document["session_token"])):
        raise CredentialsRefused("session_token_required")
    stamp = str(document["expires_at"])
    if not _TIMESTAMP.fullmatch(stamp):
        raise CredentialsRefused("credentials_malformed")
    expires = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    if expires < required_until + REQUIRED_MARGIN:
        raise CredentialsRefused("session_expires_too_soon")
    if expires > now + MAX_SESSION_LIFETIME:
        raise CredentialsRefused("session_lifetime_implausible")
    name = str(document["session_name"])
    if not SESSION_NAME.fullmatch(operator) or name != operator:
        raise CredentialsRefused("session_name_not_operator")
    return SessionCredentials(
        access_key_id=key,
        secret_access_key=str(document["secret_access_key"]),
        session_token=str(document["session_token"]),
        expires_at=expires,
        session_name=name,
    )
