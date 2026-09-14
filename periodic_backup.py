"""Verified, self-contained periodic backups for one LCM SQLite store.

Automatic restore is intentionally absent.  A successful generation contains a
transactionally consistent SQLite image plus every externalized payload that the
staged image can actually load.  Publication, pointer update, and retention are
serialized by a nonblocking POSIX advisory lock scoped to the canonical source
DB namespace.  Other platforms fail closed; the existing manual backup and
rotate operations remain portable and unchanged.

The guarantee is for local filesystems.  ``flock`` and directory ``fsync`` do
not establish a distributed lock or durability contract on network filesystems.
Canonical source and destination paths resolve symlink aliases before identity
is computed.  Symlinks, reparse points, and multiply-linked payload files are
rejected; hardlink aliases of the source database are not claimed to share an
identity.
"""

from __future__ import annotations

import codecs
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
from typing import Any, Callable
from urllib.parse import quote
import uuid

from .externalize import (
    _StreamingJSONReader,
    _stream_json_read_number,
    _stream_json_skip_value,
    _stream_json_skip_whitespace,
    get_large_output_storage_dir,
)
logger = logging.getLogger(__name__)

BUNDLE_SCHEMA = "lcm-periodic-backup/v1"
POINTER_SCHEMA = "lcm-periodic-backup-pointer/v1"
SOURCE_IDENTITY_VERSION = 1
_GENERATION_PREFIX = "lcm-periodic-"
_LOCK_NAME = ".periodic-backup.lock"
_POINTER_NAME = "latest-good.json"
_STAGING_OWNER_NAME = ".owner.json"
_STAGING_SCHEMA = "lcm-periodic-backup-staging/v1"
_BACKUP_BUSY_TIMEOUT_SECONDS = 5.0
_BACKUP_MAX_SECONDS = 300.0
_MAX_METADATA_BYTES = 4 * 1024 * 1024
# Each generated payload record has three fixed keys, one bounded filesystem
# basename, one platform file-size integer, and one SHA-256 digest.  Manifest
# allowance grows only with the safe entries actually present in the bundle.
_MANIFEST_PAYLOAD_ENTRY_OVERHEAD_BYTES = 256
_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS = 10.0
_MAX_FAILURE_BACKOFF_SECONDS = 300.0
_INGEST_MARKER_RE = re.compile(
    r"\[Externalized LCM ingest payload:.*?;\s*ref=(?P<ref>[^;\]\s]+)\]"
)
_EXTERNALIZED_MARKER_RE = re.compile(
    r"\[(?:Externalized|GC'd externalized) (?:tool output|payload):.*?;\s*ref=(?P<ref>[^;\]\s]+)\]"
)
_STAGING_NAME_RE = re.compile(
    r"^(?P<generation>lcm-periodic-\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{12})\.partial$"
)
_QUARANTINED_ASSISTANT_KIND = "quarantined_assistant_output"
_EXAMPLE_REF_PREFIXES = (
    "example-",
    "example_",
    "fake-",
    "fake_",
    "dummy-",
    "dummy_",
    "placeholder-",
    "placeholder_",
)

try:  # POSIX only by contract; Windows automatic backups fail closed.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised through capability tests
    _fcntl = None

FaultHook = Callable[[str], None]


class PeriodicBackupError(RuntimeError):
    """A generation cannot be safely produced or verified."""


class PeriodicBackupUnsupported(PeriodicBackupError):
    """Required local locking or durability primitives are unavailable."""


class PeriodicBackupCancelled(PeriodicBackupError):
    """Scheduler shutdown cancelled an in-progress snapshot."""


class PointerPublicationError(PeriodicBackupError):
    def __init__(self, message: str, *, renamed: bool):
        super().__init__(message)
        self.renamed = renamed


@dataclass(frozen=True)
class PeriodicBackupSpec:
    source_db: Path
    source_identity: str
    payload_root: Path
    destination_root: Path
    namespace: Path
    interval_seconds: float
    keep_last: int
    # Captured at admission. A path-only spec is not safe to publish from:
    # replacing the directory at the same pathname must fail closed.
    payload_root_binding: PayloadRootBinding | None = None


@dataclass(frozen=True)
class PolicyFingerprint:
    """Immutable admission policy for one canonical backup source."""

    destination_root: Path
    interval_seconds: float
    keep_last: int
    expected_root: Path


@dataclass
class PeriodicBackupRegistration:
    source_key: str
    owner: object
    active: bool
    error: str = ""
    state: str = "disabled"
    reason: str = ""
    # A rejected reconfiguration must remain releasable without pretending the
    # rejected policy owns a lease. Shutdown follows this admitted handle.
    retained_registration: "PeriodicBackupRegistration | None" = None


@dataclass(frozen=True)
class PayloadRootBinding:
    """One immutable, locally verified payload-root admission value."""

    path: Path
    device: int
    inode: int


@dataclass(frozen=True)
class OwnerRecord:
    """Immutable admission authority plus the owner's current eligibility."""

    owner_id: object
    admitted_policy_fingerprint: PolicyFingerprint
    admitted_root_binding: PayloadRootBinding | None
    admission_generation: int
    state: str
    release_handle: PeriodicBackupRegistration


def _payload_root_binding(path: Path) -> PayloadRootBinding:
    resolved = path.expanduser().resolve(strict=False)
    try:
        observed = os.lstat(resolved)
    except FileNotFoundError as exc:
        raise PeriodicBackupError("periodic payload root does not exist") from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise PeriodicBackupError("periodic payload root is not a plain directory")
    if not _owned_by_current_user(observed):
        raise PeriodicBackupError("periodic payload root is not owned by this user")
    if stat.S_IMODE(observed.st_mode) & 0o077:
        raise PeriodicBackupError("periodic payload root is not private")
    return PayloadRootBinding(resolved, observed.st_dev, observed.st_ino)


@dataclass(frozen=True)
class _RecoveryReference:
    ref: str
    marker: str
    marker_type: str
    session_id: str
    role: str
    field: str


@dataclass(frozen=True)
class _PayloadDirectoryInventory:
    names: frozenset[str]
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PeriodicBackupError("backup timestamp is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PeriodicBackupError("backup timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise PeriodicBackupError("backup timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _source_identity(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()


def _validate_destination_admission(path: Path) -> None:
    """Reject existing unsafe destination components without creating anything."""
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    current = Path(candidate.anchor)
    for component in candidate.parts[1:]:
        current /= component
        try:
            observed = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(observed.st_mode):
            try:
                observed = os.stat(current)
            except FileNotFoundError as exc:
                raise PeriodicBackupError(
                    f"backup path has a broken symlink component: {current}"
                ) from exc
        if not stat.S_ISDIR(observed.st_mode):
            raise PeriodicBackupError(f"backup path is not a plain directory: {current}")


def _validate_admission_primitives() -> None:
    """Check mandatory local durability primitives before scheduler allocation."""
    if _fcntl is None:
        raise PeriodicBackupUnsupported("POSIX flock is required")
    if os.name != "posix" or not hasattr(os, "O_DIRECTORY"):
        raise PeriodicBackupUnsupported("directory fsync is unsupported on this platform")


def build_periodic_backup_spec(
    engine,
    *,
    allow_missing_payload_root: bool = False,
) -> PeriodicBackupSpec:
    """Resolve immutable scheduler settings without creating backup state."""
    # LCMConfig validates at construction, but runtime reconfiguration can mutate
    # its fields before a later engine/lease admission. Re-run the authoritative
    # scalar validator before resolving paths or allocating any scheduler state.
    try:
        engine._config.validate_periodic_backup()
    except ValueError as exc:
        raise PeriodicBackupError(str(exc)) from exc
    raw_db = str(engine._store.db_path)
    if raw_db == ":memory:":
        raise PeriodicBackupUnsupported("periodic backup does not support in-memory databases")
    source_db = Path(raw_db).expanduser().resolve(strict=True)
    source_stat = os.lstat(source_db)
    if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
        raise PeriodicBackupError("source database is not a regular file")

    configured_root = str(getattr(engine._config, "periodic_backup_path", "") or "")
    raw_root = Path(configured_root).expanduser() if configured_root else engine.backup_dir() / "periodic"
    _validate_destination_admission(raw_root)
    _validate_admission_primitives()
    destination_root = raw_root.resolve(strict=False)
    identity = _source_identity(source_db)
    payload_root = get_large_output_storage_dir(
        engine._config,
        hermes_home=str(getattr(engine, "_hermes_home", "") or ""),
        create=False,
    ).resolve(strict=False)
    try:
        interval_seconds = float(engine._config.periodic_backup_interval_hours) * 3600.0
    except (TypeError, ValueError, OverflowError) as exc:
        raise PeriodicBackupError("periodic backup interval is invalid") from exc
    if (
        not math.isfinite(interval_seconds)
        or interval_seconds <= 0.0
        or interval_seconds > threading.TIMEOUT_MAX
    ):
        raise PeriodicBackupError(
            "periodic backup interval is invalid or exceeds the platform scheduler timeout limit"
        )
    try:
        payload_root_binding = _payload_root_binding(payload_root)
    except PeriodicBackupError:
        if not allow_missing_payload_root or payload_root.exists():
            raise
        payload_root_binding = None
    return PeriodicBackupSpec(
        source_db=source_db,
        source_identity=identity,
        payload_root=payload_root,
        destination_root=destination_root,
        namespace=destination_root / identity,
        interval_seconds=interval_seconds,
        keep_last=engine._config.periodic_backup_keep_last,
        payload_root_binding=payload_root_binding,
    )


def _identity_payload(spec: PeriodicBackupSpec) -> dict[str, Any]:
    return {
        "version": SOURCE_IDENTITY_VERSION,
        "canonical_db_path": str(spec.source_db),
        "sha256": spec.source_identity,
    }


def _identity_matches(value: Any, spec: PeriodicBackupSpec) -> bool:
    return isinstance(value, dict) and value == _identity_payload(spec)


def _owned_by_current_user(file_stat: os.stat_result) -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is None or getattr(file_stat, "st_uid", None) in (None, geteuid())


def _private_directory(path: Path, *, preserve_existing: bool = False) -> None:
    existed = False
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        existed = True
    observed = os.lstat(path)
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise PeriodicBackupError(f"backup path is not a plain directory: {path}")
    if existed and preserve_existing:
        return
    if existed and not _owned_by_current_user(observed):
        raise PeriodicBackupError(f"existing backup path is not owned by this user: {path}")
    path.chmod(0o700)


def _prepare_private_directory_tree(path: Path) -> None:
    """Create each missing directory and durably publish its parent entry."""
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for component in reversed(missing):
        _private_directory(component)
        _fsync_directory(component.parent)
    _private_directory(path, preserve_existing=True)


def _prepare_namespace(spec: PeriodicBackupSpec) -> None:
    _prepare_private_directory_tree(spec.destination_root)
    expected_root = spec.destination_root.resolve(strict=True)
    if spec.namespace.parent.resolve(strict=True) != expected_root:
        raise PeriodicBackupError("backup namespace escaped its configured root")
    namespace_existed = spec.namespace.exists()
    _private_directory(spec.namespace)
    if not namespace_existed:
        _fsync_directory(spec.destination_root)
    if spec.namespace.resolve(strict=True).parent != expected_root:
        raise PeriodicBackupError("backup namespace identity changed during creation")


def _fsync_directory(path: Path) -> None:
    if os.name != "posix" or not hasattr(os, "O_DIRECTORY"):
        raise PeriodicBackupUnsupported("directory fsync is unsupported on this platform")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise PeriodicBackupUnsupported(f"cannot open directory for fsync: {path}: {exc}") from exc
    try:
        observed = os.fstat(fd)
        if not stat.S_ISDIR(observed.st_mode):
            raise PeriodicBackupUnsupported(f"fsync target is not a directory: {path}")
        try:
            os.fsync(fd)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise PeriodicBackupUnsupported(f"directory fsync failed for {path}: {exc}") from exc
    finally:
        os.close(fd)


def _fsync_file(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            raise PeriodicBackupError(f"fsync target is not a regular file: {path}")
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_private_file(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while publishing backup metadata")
            view = view[written:]
        os.fsync(fd)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _read_json_regular(
    path: Path,
    *,
    max_bytes: int = _MAX_METADATA_BYTES,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    expected = os.lstat(path)
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
        raise PeriodicBackupError(f"metadata is not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
            or opened.st_size > max_bytes
        ):
            raise PeriodicBackupError(f"metadata identity or size is unsafe: {path}")
        raw = bytearray()
        deadline = time.monotonic() + _BACKUP_MAX_SECONDS
        while len(raw) <= max_bytes:
            if cancel is not None and cancel.is_set():
                raise PeriodicBackupCancelled("periodic backup cancelled during metadata read")
            if time.monotonic() >= deadline:
                raise PeriodicBackupError("metadata read exceeded its bounded deadline")
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        current = os.lstat(path)
        if (
            (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_size != opened.st_size
            or current.st_mtime_ns != opened.st_mtime_ns
            or len(raw) > max_bytes
        ):
            raise PeriodicBackupError(f"metadata changed during read: {path}")
        value = json.loads(bytes(raw).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PeriodicBackupError(f"invalid metadata file: {path}") from exc
    finally:
        os.close(fd)
    if not isinstance(value, dict):
        raise PeriodicBackupError(f"metadata must be a JSON object: {path}")
    return value


def _sha256_file(
    path: Path,
    *,
    cancel: threading.Event | None = None,
) -> tuple[int, str]:
    expected = os.lstat(path)
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
        raise PeriodicBackupError(f"hashed backup entry is not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise PeriodicBackupError(f"hashed backup entry changed during open: {path}")
        while True:
            if cancel is not None and cancel.is_set():
                raise PeriodicBackupCancelled("periodic backup cancelled during verification")
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        current = os.lstat(path)
        if (
            (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_size != opened.st_size
            or current.st_mtime_ns != opened.st_mtime_ns
            or size != opened.st_size
        ):
            raise PeriodicBackupError(f"hashed backup entry changed during read: {path}")
    finally:
        os.close(fd)
    return size, digest.hexdigest()


def _integrity_check(
    path: Path,
    *,
    cancel: threading.Event | None = None,
) -> None:
    uri = f"file:{quote(str(path), safe='/')}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, timeout=_BACKUP_BUSY_TIMEOUT_SECONDS)
    try:
        if cancel is not None:
            conn.set_progress_handler(lambda: 1 if cancel.is_set() else 0, 1000)
        rows = conn.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.OperationalError as exc:
        if cancel is not None and cancel.is_set():
            raise PeriodicBackupCancelled(
                "periodic backup cancelled during SQLite verification"
            ) from exc
        raise
    finally:
        conn.close()
    if rows != [("ok",)]:
        raise PeriodicBackupError(f"SQLite integrity_check rejected staged backup: {rows!r}")


def _snapshot_database(
    spec: PeriodicBackupSpec,
    destination: Path,
    *,
    cancel: threading.Event | None,
) -> None:
    source_before = os.lstat(spec.source_db)
    if stat.S_ISLNK(source_before.st_mode) or not stat.S_ISREG(source_before.st_mode):
        raise PeriodicBackupError("source database is not a stable regular file")
    _create_private_file(destination)
    source_uri = f"file:{quote(str(spec.source_db), safe='/')}?mode=ro"
    source = sqlite3.connect(source_uri, uri=True, timeout=_BACKUP_BUSY_TIMEOUT_SECONDS)
    target = sqlite3.connect(str(destination), timeout=_BACKUP_BUSY_TIMEOUT_SECONDS)
    deadline = time.monotonic() + _BACKUP_MAX_SECONDS

    def progress(_status: int, _remaining: int, _total: int) -> None:
        if cancel is not None and cancel.is_set():
            raise PeriodicBackupCancelled("periodic backup cancelled during SQLite snapshot")
        if time.monotonic() >= deadline:
            raise PeriodicBackupError("periodic SQLite snapshot exceeded its bounded deadline")

    try:
        source.execute(f"PRAGMA busy_timeout={int(_BACKUP_BUSY_TIMEOUT_SECONDS * 1000)}")
        target.execute(f"PRAGMA busy_timeout={int(_BACKUP_BUSY_TIMEOUT_SECONDS * 1000)}")
        source.backup(target, pages=128, progress=progress, sleep=0.05)
    finally:
        target.close()
        source.close()
    source_after = os.lstat(spec.source_db)
    if (source_after.st_dev, source_after.st_ino) != (
        source_before.st_dev,
        source_before.st_ino,
    ):
        raise PeriodicBackupError("source database path changed during snapshot")
    destination.chmod(0o600)
    _fsync_file(destination)


def _snapshot_recovery_references(spec: PeriodicBackupSpec) -> list[_RecoveryReference]:
    """Enumerate recovery references from a fresh, isolated SQLite snapshot."""
    with tempfile.TemporaryDirectory(prefix="lcm-periodic-readmission-") as directory:
        snapshot = Path(directory) / "lcm.sqlite3"
        _snapshot_database(spec, snapshot, cancel=None)
        _integrity_check(snapshot, cancel=None)
        return _enumerate_recovery_refs(snapshot, cancel=None)


def _verify_readmission_payloads(
    binding: PayloadRootBinding,
    references: list[_RecoveryReference],
    *,
    manifest_payloads: list[dict[str, Any]] | None = None,
) -> None:
    """Prove one candidate root contains safe bytes for all named references."""
    observed_binding = _payload_root_binding(binding.path)
    if (
        observed_binding != binding
        or binding.device == 0
        or binding.inode == 0
        or not binding.path.exists()
    ):
        raise PeriodicBackupError("candidate payload root identity is not stable")

    expected: dict[str, dict[str, Any]] = {}
    if manifest_payloads is not None:
        for entry in manifest_payloads:
            name = entry.get("basename") if isinstance(entry, dict) else None
            if (
                not isinstance(name, str)
                or Path(name).name != name
                or name in expected
                or not isinstance(entry.get("size"), int)
                or not isinstance(entry.get("sha256"), str)
            ):
                raise PeriodicBackupError("retained generation manifest payload is invalid")
            expected[name] = entry

    names = {reference.ref for reference in references}
    if manifest_payloads is not None and names != set(expected):
        raise PeriodicBackupError("retained generation references do not match its manifest")
    for name in names:
        if not name or Path(name).name != name:
            raise PeriodicBackupError(f"invalid externalized payload reference: {name!r}")
        payload = binding.path / name
        try:
            metadata = os.lstat(payload)
        except FileNotFoundError as exc:
            raise PeriodicBackupError(f"candidate payload is missing: {name}") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_nlink", 1) != 1
        ):
            raise PeriodicBackupError(f"candidate payload is unsafe: {name}")
        size, digest = _sha256_file(payload)
        if manifest_payloads is not None and expected[name] != {
            "basename": name,
            "size": size,
            "sha256": digest,
        }:
            raise PeriodicBackupError(
                f"candidate payload bytes differ from retained generation: {name}"
            )
    _verify_payload_recovery(binding.path, references, cancel=None)


def _marker_metadata(marker: str, key: str) -> str:
    match = re.search(rf"(?:^|[:;])\s*{re.escape(key)}=([^;\]\s]+)", marker)
    return match.group(1) if match is not None else ""


def _placeholder_metadata_value(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.:/-]+", "-", str(value or "?")).strip("-")
    return (safe or "?")[:120]


def _looks_like_quoted_or_template_example(
    text: str,
    *,
    start: int,
    end: int,
    ref: str,
) -> bool:
    if not Path(ref).name.lower().startswith(_EXAMPLE_REF_PREFIXES):
        return False
    before = text[:start].rstrip()
    after = text[end:].lstrip()
    if before.endswith(("{{", "{%")) and after.startswith(("}}", "%}")):
        return True
    for quote_char in ('"', "'"):
        if before.endswith(quote_char) and after.startswith(quote_char):
            return True
        if before.endswith("\\" + quote_char) and after.startswith("\\" + quote_char):
            return True
    return False


def _references_in_text(
    text: str,
    *,
    session_id: str,
    role: str,
    field: str,
    allow_embedded: bool,
) -> list[_RecoveryReference]:
    if not isinstance(text, str) or not text:
        return []
    stripped = text.strip()
    refs: list[_RecoveryReference] = []
    matches = [
        (match, "ingest") for match in _INGEST_MARKER_RE.finditer(text)
    ] + [
        (match, "externalized") for match in _EXTERNALIZED_MARKER_RE.finditer(text)
    ]
    for match, marker_type in sorted(matches, key=lambda item: item[0].start()):
        marker = match.group(0)
        exact = marker == stripped
        if not exact and not allow_embedded:
            continue
        ref = match.group("ref").strip()
        if not exact and _looks_like_quoted_or_template_example(
            text,
            start=match.start(),
            end=match.end(),
            ref=ref,
        ):
            continue
        reference = _RecoveryReference(
            ref=ref,
            marker=marker,
            marker_type=marker_type,
            session_id=session_id,
            role=role,
            field=field,
        )
        if reference not in refs:
            refs.append(reference)
    return refs


def _walk_recovery_references(
    value: Any,
    *,
    session_id: str,
    role: str,
    field: str,
) -> list[_RecoveryReference]:
    refs: list[_RecoveryReference] = []

    def visit(item: Any) -> None:
        if isinstance(item, str):
            for reference in _references_in_text(
                item,
                session_id=session_id,
                role=role,
                field=field,
                allow_embedded=True,
            ):
                if reference not in refs:
                    refs.append(reference)
            stripped = item.strip()
            if stripped.startswith(("{", "[")):
                try:
                    nested = json.loads(stripped)
                except json.JSONDecodeError:
                    return
                if not isinstance(nested, str):
                    visit(nested)
            return
        if isinstance(item, list):
            for nested in item:
                visit(nested)
            return
        if isinstance(item, dict):
            for key, nested in item.items():
                visit(key)
                visit(nested)

    visit(value)
    return refs


def _enumerate_recovery_refs(
    staged_db: Path,
    *,
    cancel: threading.Event | None,
) -> list[_RecoveryReference]:
    """Enumerate record-context refs that the production recovery paths consume."""
    uri = f"file:{quote(str(staged_db), safe='/')}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, timeout=_BACKUP_BUSY_TIMEOUT_SECONDS)
    refs: list[_RecoveryReference] = []
    try:
        if cancel is not None:
            conn.set_progress_handler(lambda: 1 if cancel.is_set() else 0, 1000)
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='messages'"
        ).fetchone()
        if table is None:
            raise PeriodicBackupError("staged database has no messages table")
        for session_id, role, content, tool_calls in conn.execute(
            "SELECT session_id, role, content, tool_calls FROM messages ORDER BY store_id ASC"
        ):
            if cancel is not None and cancel.is_set():
                raise PeriodicBackupCancelled(
                    "periodic backup cancelled during reference enumeration"
                )
            for reference in _walk_recovery_references(
                content,
                session_id=str(session_id or ""),
                role=str(role or ""),
                field="content",
            ):
                if reference not in refs:
                    refs.append(reference)
            if not isinstance(tool_calls, str) or not tool_calls:
                continue
            try:
                parsed = json.loads(tool_calls)
            except json.JSONDecodeError as exc:
                unresolved = _references_in_text(
                    tool_calls,
                    session_id=str(session_id or ""),
                    role=str(role or ""),
                    field="tool_calls",
                    allow_embedded=True,
                )
                if unresolved:
                    raise PeriodicBackupError(
                        "tool_calls contains an unresolved externalized reference"
                    ) from exc
                continue
            for reference in _walk_recovery_references(
                parsed,
                session_id=str(session_id or ""),
                role=str(role or ""),
                field="tool_calls",
            ):
                if reference not in refs:
                    refs.append(reference)
    finally:
        conn.close()
    return sorted(
        refs,
        key=lambda item: (
            item.ref,
            item.session_id,
            item.role,
            item.field,
            item.marker,
        ),
    )


def _owned_regular_file(file_stat: os.stat_result) -> bool:
    return _owned_by_current_user(file_stat)


def _copy_payload(
    spec: PeriodicBackupSpec,
    ref: str,
    destination: Path,
    *,
    cancel: threading.Event | None,
) -> dict[str, Any]:
    if not ref.endswith(".json") or Path(ref).name != ref or "/" in ref or "\\" in ref:
        raise PeriodicBackupError(f"invalid externalized payload reference: {ref!r}")
    if not spec.payload_root.exists():
        raise PeriodicBackupError(f"referenced payload store does not exist: {spec.payload_root}")
    expected_dir = os.lstat(spec.payload_root)
    if stat.S_ISLNK(expected_dir.st_mode) or not stat.S_ISDIR(expected_dir.st_mode):
        raise PeriodicBackupError("externalized payload store is not a plain directory")
    if spec.payload_root.resolve(strict=True) != spec.payload_root:
        raise PeriodicBackupError("externalized payload store changed canonical identity")
    binding = spec.payload_root_binding
    if binding is not None and (
        binding.path != spec.payload_root
        or (expected_dir.st_dev, expected_dir.st_ino) != (binding.device, binding.inode)
    ):
        raise PeriodicBackupError("externalized payload store changed approved root identity")

    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(spec.payload_root, dir_flags)
    source_fd = -1
    destination_fd = -1
    try:
        opened_dir = os.fstat(dir_fd)
        if (opened_dir.st_dev, opened_dir.st_ino) != (expected_dir.st_dev, expected_dir.st_ino):
            raise PeriodicBackupError("externalized payload store changed during backup")
        before = os.stat(ref, dir_fd=dir_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or getattr(before, "st_nlink", 1) != 1
            or not _owned_regular_file(before)
        ):
            raise PeriodicBackupError(f"referenced payload is not a safe regular file: {ref}")
        source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        source_fd = os.open(ref, source_flags, dir_fd=dir_fd)
        opened = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise PeriodicBackupError(f"referenced payload changed during open: {ref}")

        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        destination_fd = os.open(destination, destination_flags, 0o600)
        digest = hashlib.sha256()
        size = 0
        deadline = time.monotonic() + _BACKUP_MAX_SECONDS
        while True:
            if cancel is not None and cancel.is_set():
                raise PeriodicBackupCancelled("periodic backup cancelled during payload copy")
            if time.monotonic() >= deadline:
                raise PeriodicBackupError(
                    "externalized payload copy exceeded its bounded deadline"
                )
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("short write while copying externalized payload")
                view = view[written:]
        os.fsync(destination_fd)
        if hasattr(os, "fchmod"):
            os.fchmod(destination_fd, 0o600)
        after = os.stat(ref, dir_fd=dir_fd, follow_symlinks=False)
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or getattr(after, "st_ctime_ns", None) != getattr(opened, "st_ctime_ns", None)
            or size != opened.st_size
        ):
            raise PeriodicBackupError(f"referenced payload changed during copy: {ref}")
        return {"basename": ref, "size": size, "sha256": digest.hexdigest()}
    except FileNotFoundError as exc:
        raise PeriodicBackupError(f"referenced payload is missing: {ref}") from exc
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)
        os.close(dir_fd)


class _BoundedPayloadJSONReader(_StreamingJSONReader):
    def __init__(
        self,
        handle,
        *,
        cancel: threading.Event | None,
    ) -> None:
        super().__init__(handle, start=0)
        self._cancel = cancel
        self._deadline = time.monotonic() + _BACKUP_MAX_SECONDS

    def peek(self) -> int | None:
        if self._index >= len(self._buffer):
            if self._cancel is not None and self._cancel.is_set():
                raise PeriodicBackupCancelled(
                    "periodic backup cancelled during payload validation"
                )
            if time.monotonic() >= self._deadline:
                raise PeriodicBackupError(
                    "externalized payload validation exceeded its bounded deadline"
                )
        return super().peek()


def _read_json_hex_escape(reader: _BoundedPayloadJSONReader) -> int:
    raw = bytearray()
    for _ in range(4):
        byte = reader.read()
        if byte is None or byte not in b"0123456789abcdefABCDEF":
            raise ValueError("invalid_json_unicode_escape")
        raw.append(byte)
    return int(raw.decode("ascii"), 16)


def _stream_payload_json_read_string(
    reader: _BoundedPayloadJSONReader,
    *,
    capture_limit: int,
) -> str | None:
    """Read one bounded JSON string without mixing byte and character offsets."""
    if reader.read() != ord('"'):
        raise ValueError("invalid_json_string")
    raw = bytearray()
    truncated = False
    escaped = False
    unicode_digits_remaining = 0
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    while True:
        byte = reader.read()
        if byte is None:
            raise ValueError("truncated_json_string")
        if unicode_digits_remaining:
            if byte not in b"0123456789abcdefABCDEF":
                raise ValueError("invalid_json_unicode_escape")
            unicode_digits_remaining -= 1
        elif escaped:
            if byte == ord("u"):
                unicode_digits_remaining = 4
            elif byte not in b'"\\/bfnrt':
                raise ValueError("invalid_json_escape")
            escaped = False
        elif byte == ord("\\"):
            escaped = True
        elif byte == ord('"'):
            decoder.decode(b"", final=True)
            if truncated:
                return None
            source = (b'"' + bytes(raw) + b'"').decode("utf-8")
            value, end = json.JSONDecoder().raw_decode(source)
            if end != len(source) or not isinstance(value, str):
                raise ValueError("invalid_json_string")
            return value
        elif byte < 0x20:
            raise ValueError("invalid_json_control_character")
        decoder.decode(bytes((byte,)), final=False)
        if len(raw) < capture_limit:
            raw.append(byte)
        else:
            truncated = True


def _stream_json_content_metrics(
    reader: _BoundedPayloadJSONReader,
) -> tuple[int, int]:
    if reader.read() != ord('"'):
        raise ValueError("payload_content_is_not_string")
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    content_chars = 0
    content_bytes = 0
    simple_escapes = {
        ord('"'): '"',
        ord("\\"): "\\",
        ord("/"): "/",
        ord("b"): "\b",
        ord("f"): "\f",
        ord("n"): "\n",
        ord("r"): "\r",
        ord("t"): "\t",
    }
    while True:
        if reader.peek() is None:
            raise ValueError("truncated_json_string")
        start = reader._index
        quote_at = reader._buffer.find(b'"', start)
        escape_at = reader._buffer.find(b"\\", start)
        special_positions = [
            position for position in (quote_at, escape_at) if position >= 0
        ]
        special_at = min(special_positions) if special_positions else len(reader._buffer)
        raw = reader._buffer[start:special_at]
        if raw:
            if min(raw) < 0x20:
                raise ValueError("invalid_json_control_character")
            decoded = decoder.decode(raw, final=False)
            content_chars += len(decoded)
            content_bytes += len(raw)
            reader._index = special_at
        if special_at >= len(reader._buffer):
            continue

        byte = reader.read()
        if byte == ord('"'):
            final = decoder.decode(b"", final=True)
            content_chars += len(final)
            return content_chars, content_bytes
        final = decoder.decode(b"", final=True)
        content_chars += len(final)
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        escaped = reader.read()
        if escaped == ord("u"):
            codepoint = _read_json_hex_escape(reader)
            if 0xD800 <= codepoint <= 0xDBFF:
                if reader.read() != ord("\\") or reader.read() != ord("u"):
                    raise ValueError("invalid_json_surrogate_pair")
                low = _read_json_hex_escape(reader)
                if not 0xDC00 <= low <= 0xDFFF:
                    raise ValueError("invalid_json_surrogate_pair")
                codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
            elif 0xDC00 <= codepoint <= 0xDFFF:
                raise ValueError("invalid_json_surrogate_pair")
            value = chr(codepoint)
        else:
            value = simple_escapes.get(escaped)
            if value is None:
                raise ValueError("invalid_json_escape")
        content_chars += 1
        content_bytes += len(value.encode("utf-8"))


def _stream_payload_document(
    path: Path,
    *,
    cancel: threading.Event | None,
) -> dict[str, Any]:
    captured_strings = {"kind", "tool_call_id", "role", "session_id", "field_path"}
    captured_numbers = {"content_chars", "content_bytes", "created_at"}
    decoded: dict[str, Any] = {}
    content_metrics: tuple[int, int] | None = None
    with path.open("rb") as handle:
        reader = _BoundedPayloadJSONReader(handle, cancel=cancel)
        _stream_json_skip_whitespace(reader)
        if reader.read() != ord("{"):
            raise ValueError("payload_is_not_json_object")
        _stream_json_skip_whitespace(reader)
        if reader.peek() == ord("}"):
            reader.read()
        else:
            while True:
                key = _stream_payload_json_read_string(reader, capture_limit=256)
                _stream_json_skip_whitespace(reader)
                if reader.read() != ord(":"):
                    raise ValueError("invalid_payload_object")
                _stream_json_skip_whitespace(reader)
                if key == "content":
                    if reader.peek() != ord('"'):
                        _stream_json_skip_value(reader, depth=1)
                        content_metrics = None
                    else:
                        content_metrics = _stream_json_content_metrics(reader)
                elif key in captured_strings:
                    if reader.peek() == ord('"'):
                        value = _stream_payload_json_read_string(
                            reader,
                            capture_limit=_MAX_METADATA_BYTES,
                        )
                        decoded[key] = value if value is not None else object()
                    else:
                        value_type = reader.peek()
                        _stream_json_skip_value(reader, depth=1)
                        decoded[key] = None if value_type == ord("n") else object()
                elif key in captured_numbers:
                    if reader.peek() in (ord("-"), *range(ord("0"), ord("9") + 1)):
                        raw_number = _stream_json_read_number(reader)
                        decoded[key] = (
                            json.loads(raw_number) if raw_number is not None else object()
                        )
                    else:
                        value_type = reader.peek()
                        _stream_json_skip_value(reader, depth=1)
                        decoded[key] = None if value_type == ord("n") else object()
                else:
                    _stream_json_skip_value(reader, depth=1)
                _stream_json_skip_whitespace(reader)
                separator = reader.read()
                if separator == ord("}"):
                    break
                if separator != ord(","):
                    raise ValueError("invalid_payload_object")
                _stream_json_skip_whitespace(reader)
        _stream_json_skip_whitespace(reader)
        if reader.peek() is not None:
            raise ValueError("trailing_payload_data")
    if content_metrics is None:
        raise ValueError("payload_content_is_not_string")
    decoded["_actual_content_chars"] = content_metrics[0]
    decoded["_actual_content_bytes"] = content_metrics[1]
    return decoded


def _read_payload_document(
    payload_dir: Path,
    ref: str,
    *,
    cancel: threading.Event | None,
) -> dict[str, Any]:
    try:
        decoded = _stream_payload_document(payload_dir / ref, cancel=cancel)
    except PeriodicBackupCancelled:
        raise
    except PeriodicBackupError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PeriodicBackupError(f"copied payload is not valid JSON: {ref}") from exc
    for key in ("kind", "tool_call_id", "role", "session_id", "field_path"):
        value = decoded.get(key)
        if value is not None and not isinstance(value, str):
            raise PeriodicBackupError(f"copied payload {key} is not text: {ref}")
    for key, actual_key in (
        ("content_chars", "_actual_content_chars"),
        ("content_bytes", "_actual_content_bytes"),
    ):
        declared = decoded.get(key)
        if declared is not None and (
            isinstance(declared, bool)
            or not isinstance(declared, int)
            or declared != decoded[actual_key]
        ):
            raise PeriodicBackupError(f"copied payload {key} is invalid: {ref}")
    created_at = decoded.get("created_at")
    if created_at is not None and (
        isinstance(created_at, bool)
        or not isinstance(created_at, (int, float))
        or not math.isfinite(float(created_at))
    ):
        raise PeriodicBackupError(f"copied payload created_at is invalid: {ref}")
    return decoded


def _validate_payload_context(
    payload_dir: Path,
    reference: _RecoveryReference,
    *,
    cancel: threading.Event | None,
) -> None:
    payload = _read_payload_document(payload_dir, reference.ref, cancel=cancel)
    payload_session = str(payload.get("session_id") or "")
    if payload_session and reference.session_id and payload_session != reference.session_id:
        raise PeriodicBackupError(
            f"copied payload session identity mismatch: {reference.ref}"
        )
    payload_role = str(payload.get("role") or "")
    if payload_role and reference.role and payload_role != reference.role:
        raise PeriodicBackupError(f"copied payload role mismatch: {reference.ref}")

    if reference.marker_type == "ingest":
        marker_kind = _marker_metadata(reference.marker, "kind")
        payload_kind = str(payload.get("kind") or "")
        if marker_kind != payload_kind:
            raise PeriodicBackupError(f"copied ingest payload kind mismatch: {reference.ref}")
        marker_field = _marker_metadata(reference.marker, "field")
        payload_field = str(payload.get("field_path") or "")
        if marker_field and _placeholder_metadata_value(payload_field) != marker_field:
            raise PeriodicBackupError(f"copied ingest payload field mismatch: {reference.ref}")
        if payload_field and not (
            payload_field == reference.field
            or payload_field.startswith(reference.field + ".")
            or payload_field.startswith(reference.field + "[")
        ):
            raise PeriodicBackupError(f"copied ingest payload field context mismatch: {reference.ref}")
        if payload_kind == _QUARANTINED_ASSISTANT_KIND:
            if payload_session != reference.session_id or not payload_session:
                raise PeriodicBackupError(
                    f"copied quarantined payload session identity mismatch: {reference.ref}"
                )
            if reference.role != "assistant" or payload_role != "assistant":
                raise PeriodicBackupError(
                    f"copied quarantined payload role mismatch: {reference.ref}"
                )
            if reference.field != "content" or payload_field != "content":
                raise PeriodicBackupError(
                    f"copied quarantined payload field context mismatch: {reference.ref}"
                )
            if "assistant output quarantined" not in reference.marker:
                raise PeriodicBackupError(
                    f"copied quarantined payload marker mismatch: {reference.ref}"
                )
        elif payload_kind != "ingest_payload":
            raise PeriodicBackupError(f"ingest marker kind is unsupported: {reference.ref}")
    else:
        expected_kind = _marker_metadata(reference.marker, "kind")
        if not expected_kind and "tool output:" in reference.marker:
            expected_kind = "tool_result"
        actual_kind = str(payload.get("kind") or "tool_result")
        if expected_kind and actual_kind != expected_kind:
            raise PeriodicBackupError(f"copied payload kind mismatch: {reference.ref}")
        marker_role = _marker_metadata(reference.marker, "role")
        if marker_role and payload_role and marker_role != payload_role:
            raise PeriodicBackupError(f"copied payload marker role mismatch: {reference.ref}")
        marker_call_id = _marker_metadata(reference.marker, "tool_call_id")
        payload_call_id = str(payload.get("tool_call_id") or "")
        if marker_call_id and marker_call_id != "?" and marker_call_id != payload_call_id:
            raise PeriodicBackupError(
                f"copied payload tool-call identity mismatch: {reference.ref}"
            )


def _verify_payload_recovery(
    payload_dir: Path,
    references: list[_RecoveryReference],
    *,
    cancel: threading.Event | None = None,
) -> None:
    for reference in references:
        if cancel is not None and cancel.is_set():
            raise PeriodicBackupCancelled("periodic backup cancelled during loader verification")
        _validate_payload_context(payload_dir, reference, cancel=cancel)


def _generation_manifest(
    spec: PeriodicBackupSpec,
    generation: Path,
    *,
    payload_names: set[str],
    expected_generation_id: str | None = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    try:
        payload_name_bytes = sum(
            len(json.dumps(name, ensure_ascii=False).encode("utf-8"))
            for name in payload_names
        )
    except UnicodeEncodeError as exc:
        raise PeriodicBackupError("generation payload basename is not valid UTF-8") from exc
    manifest_limit = (
        _MAX_METADATA_BYTES
        + payload_name_bytes
        + len(payload_names) * _MANIFEST_PAYLOAD_ENTRY_OVERHEAD_BYTES
    )
    manifest = _read_json_regular(
        generation / "manifest.json",
        max_bytes=manifest_limit,
        cancel=cancel,
    )
    expected_id = expected_generation_id or generation.name
    if manifest.get("schema") != BUNDLE_SCHEMA or manifest.get("generation_id") != expected_id:
        raise PeriodicBackupError("generation manifest schema or id mismatch")
    if not _identity_matches(manifest.get("source_identity"), spec):
        raise PeriodicBackupError("generation source identity mismatch")
    return manifest


def _safe_payload_inventory(
    payload_dir: Path,
    *,
    cancel: threading.Event | None,
) -> _PayloadDirectoryInventory:
    expected = os.lstat(payload_dir)
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISDIR(expected.st_mode):
        raise PeriodicBackupError("generation payload directory is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(payload_dir, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise PeriodicBackupError("generation payload directory changed during open")
        names: set[str] = set()
        deadline = time.monotonic() + _BACKUP_MAX_SECONDS
        with os.scandir(fd) as entries:
            for entry in entries:
                if cancel is not None and cancel.is_set():
                    raise PeriodicBackupCancelled(
                        "periodic backup cancelled during payload enumeration"
                    )
                if time.monotonic() >= deadline:
                    raise PeriodicBackupError(
                        "generation payload enumeration exceeded its bounded deadline"
                    )
                observed = entry.stat(follow_symlinks=False)
                if (
                    stat.S_ISLNK(observed.st_mode)
                    or not stat.S_ISREG(observed.st_mode)
                    or getattr(observed, "st_nlink", 1) != 1
                    or not _owned_regular_file(observed)
                ):
                    raise PeriodicBackupError(
                        f"generation payload entry is unsafe: {entry.name}"
                    )
                if entry.name in names:
                    raise PeriodicBackupError(
                        f"generation payload entry is duplicated: {entry.name}"
                    )
                names.add(entry.name)
        after = os.fstat(fd)
        current = os.lstat(payload_dir)
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_mtime_ns != opened.st_mtime_ns
            or current.st_ctime_ns != opened.st_ctime_ns
        ):
            raise PeriodicBackupError("generation payload directory changed during enumeration")
        return _PayloadDirectoryInventory(
            names=frozenset(names),
            device=after.st_dev,
            inode=after.st_ino,
            mtime_ns=after.st_mtime_ns,
            ctime_ns=after.st_ctime_ns,
        )
    finally:
        os.close(fd)


def _verify_generation(
    spec: PeriodicBackupSpec,
    generation: Path,
    *,
    expected_generation_id: str | None = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    namespace = spec.namespace.resolve(strict=True)
    observed = os.lstat(generation)
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise PeriodicBackupError("generation is not a plain directory")
    if generation.resolve(strict=True).parent != namespace:
        raise PeriodicBackupError("generation escaped its source namespace")
    payload_dir = generation / "payloads"
    initial_inventory = _safe_payload_inventory(payload_dir, cancel=cancel)
    manifest = _generation_manifest(
        spec,
        generation,
        payload_names=set(initial_inventory.names),
        expected_generation_id=expected_generation_id,
        cancel=cancel,
    )
    database = manifest.get("database")
    payloads = manifest.get("payloads")
    if not isinstance(database, dict) or not isinstance(payloads, list):
        raise PeriodicBackupError("generation manifest content is invalid")
    db_path = generation / "lcm.sqlite3"
    size, digest = _sha256_file(db_path, cancel=cancel)
    if database != {"basename": "lcm.sqlite3", "size": size, "sha256": digest, "integrity_check": "ok"}:
        raise PeriodicBackupError("generation SQLite metadata mismatch")
    _integrity_check(db_path, cancel=cancel)
    seen: set[str] = set()
    for entry in payloads:
        if not isinstance(entry, dict):
            raise PeriodicBackupError("generation payload manifest entry is invalid")
        name = entry.get("basename")
        if not isinstance(name, str) or Path(name).name != name or name in seen:
            raise PeriodicBackupError("generation payload basename is invalid or duplicated")
        seen.add(name)
        payload_path = payload_dir / name
        payload_stat = os.lstat(payload_path)
        if stat.S_ISLNK(payload_stat.st_mode) or not stat.S_ISREG(payload_stat.st_mode):
            raise PeriodicBackupError(f"generation payload is unsafe: {name}")
        item_size, item_digest = _sha256_file(payload_path, cancel=cancel)
        if entry != {"basename": name, "size": item_size, "sha256": item_digest}:
            raise PeriodicBackupError(f"generation payload metadata mismatch: {name}")
    if initial_inventory.names != seen:
        raise PeriodicBackupError("generation payload set does not match manifest")
    references = _enumerate_recovery_refs(db_path, cancel=cancel)
    expected_refs = {reference.ref for reference in references}
    if expected_refs != seen:
        raise PeriodicBackupError(
            "generation payload set does not match staged database references"
        )
    _verify_payload_recovery(payload_dir, references, cancel=cancel)
    _parse_utc(manifest.get("completed_at"))
    final_inventory = _safe_payload_inventory(payload_dir, cancel=cancel)
    if final_inventory != initial_inventory:
        raise PeriodicBackupError("generation payload directory changed during verification")
    # Recovery reads the payloads as part of the semantic validation contract,
    # but it is not itself a byte-stability proof. Rebind every manifest entry
    # after recovery and immediately before the caller may rename/publish this
    # generation. Directory identity cannot detect a same-size child rewrite.
    for entry in payloads:
        name = entry["basename"]
        payload_path = payload_dir / name
        item_size, item_digest = _sha256_file(payload_path, cancel=cancel)
        if entry != {"basename": name, "size": item_size, "sha256": item_digest}:
            raise PeriodicBackupError(
                f"generation payload metadata mismatch after recovery: {name}"
            )
    return manifest


def _read_verified_pointer(
    spec: PeriodicBackupSpec,
    *,
    cancel: threading.Event | None = None,
) -> tuple[Path, dict[str, Any]] | None:
    pointer_path = spec.namespace / _POINTER_NAME
    if not pointer_path.exists():
        return None
    pointer = _read_json_regular(pointer_path)
    if pointer.get("schema") != POINTER_SCHEMA or not _identity_matches(pointer.get("source_identity"), spec):
        raise PeriodicBackupError("latest-good pointer identity mismatch")
    generation_id = pointer.get("generation_id")
    if (
        not isinstance(generation_id, str)
        or not generation_id.startswith(_GENERATION_PREFIX)
        or Path(generation_id).name != generation_id
    ):
        raise PeriodicBackupError("latest-good pointer target is invalid")
    generation = spec.namespace / generation_id
    manifest = _verify_generation(spec, generation, cancel=cancel)
    if pointer.get("completed_at") != manifest.get("completed_at"):
        raise PeriodicBackupError("latest-good pointer timestamp mismatch")
    return generation, manifest


def _seconds_from_verified_pointer(
    spec: PeriodicBackupSpec,
    verified: tuple[Path, dict[str, Any]] | None,
    *,
    now: datetime | None = None,
) -> float:
    if verified is None:
        return 0.0
    completed = _parse_utc(verified[1]["completed_at"])
    wall_now = (now or _utc_now()).astimezone(timezone.utc)
    elapsed = max(0.0, (wall_now - completed).total_seconds())
    return max(0.0, spec.interval_seconds - elapsed)


def _verified_due_state(
    spec: PeriodicBackupSpec,
    *,
    now: datetime | None = None,
    cancel: threading.Event | None = None,
) -> tuple[float, str | None]:
    if not spec.namespace.exists():
        return 0.0, None
    try:
        verified = _read_verified_pointer(spec, cancel=cancel)
    except (OSError, sqlite3.Error, PeriodicBackupError):
        return 0.0, None
    return (
        _seconds_from_verified_pointer(spec, verified, now=now),
        verified[0].name if verified is not None else None,
    )


def _seconds_until_due(
    spec: PeriodicBackupSpec,
    *,
    now: datetime | None = None,
    cancel: threading.Event | None = None,
) -> float:
    return _verified_due_state(spec, now=now, cancel=cancel)[0]


class _NamespaceLock:
    def __init__(self, namespace: Path):
        self.namespace = namespace
        self.fd = -1

    def acquire(self) -> bool:
        if os.name != "posix" or _fcntl is None:
            raise PeriodicBackupUnsupported("POSIX flock is required for automatic periodic backup")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        self.fd = os.open(self.namespace / _LOCK_NAME, flags, 0o600)
        observed = os.fstat(self.fd)
        if not stat.S_ISREG(observed.st_mode) or getattr(observed, "st_nlink", 1) != 1:
            self.close()
            raise PeriodicBackupUnsupported("periodic backup lock inode is unsafe")
        try:
            _fcntl.flock(self.fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        except BlockingIOError:
            self.close()
            return False
        except (OSError, TypeError, AttributeError) as exc:
            self.close()
            raise PeriodicBackupUnsupported(f"periodic backup flock is unavailable: {exc}") from exc
        return True

    def close(self) -> None:
        if self.fd >= 0:
            try:
                if _fcntl is not None:
                    _fcntl.flock(self.fd, _fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = -1

    def __enter__(self) -> "_NamespaceLock":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def _cleanup_partial(path: Path) -> None:
    try:
        if path.exists() and not path.is_symlink():
            shutil.rmtree(path)
    except OSError:
        logger.warning("LCM periodic backup could not clean partial generation %s", path, exc_info=True)


def _process_is_alive(pid: Any) -> bool:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return True
    if pid == os.getpid():
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True
    return True


def _owned_plain_regular(path: Path) -> bool:
    try:
        observed = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and getattr(observed, "st_nlink", 1) == 1
        and _owned_by_current_user(observed)
    )


def _owned_staging_tree(path: Path) -> bool:
    try:
        observed = os.lstat(path)
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or not _owned_by_current_user(observed)
        ):
            return False
        entries = list(path.iterdir())
    except OSError:
        return False

    allowed_files = {
        _STAGING_OWNER_NAME,
        "lcm.sqlite3",
        "lcm.sqlite3-journal",
        "lcm.sqlite3-shm",
        "lcm.sqlite3-wal",
        "manifest.json",
    }
    for entry in entries:
        if entry.name == "payloads":
            try:
                payload_stat = os.lstat(entry)
                if (
                    stat.S_ISLNK(payload_stat.st_mode)
                    or not stat.S_ISDIR(payload_stat.st_mode)
                    or not _owned_by_current_user(payload_stat)
                ):
                    return False
                payload_entries = list(entry.iterdir())
            except OSError:
                return False
            if any(
                payload.name != Path(payload.name).name
                or not payload.name.endswith(".json")
                or not _owned_plain_regular(payload)
                for payload in payload_entries
            ):
                return False
        elif entry.name not in allowed_files or not _owned_plain_regular(entry):
            return False
    return True


def _staging_has_owned_proof(
    spec: PeriodicBackupSpec,
    path: Path,
    generation_id: str,
) -> bool:
    owner_path = path / _STAGING_OWNER_NAME
    try:
        os.lstat(owner_path)
    except FileNotFoundError:
        owner = None
    except OSError:
        return False
    else:
        try:
            owner = _read_json_regular(owner_path)
        except (OSError, PeriodicBackupError):
            return False
        if not (
            owner.get("schema") == _STAGING_SCHEMA
            and owner.get("generation_id") == generation_id
            and _identity_matches(owner.get("source_identity"), spec)
        ):
            return False
        if _process_is_alive(owner.get("creator_pid")):
            return False
        return True

    try:
        manifest = _read_json_regular(path / "manifest.json")
    except (OSError, PeriodicBackupError):
        return False
    return (
        manifest.get("schema") == BUNDLE_SCHEMA
        and manifest.get("generation_id") == generation_id
        and _identity_matches(manifest.get("source_identity"), spec)
    )


def _cleanup_abandoned_staging(spec: PeriodicBackupSpec) -> list[str]:
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        return []
    deleted: list[str] = []
    for candidate in spec.namespace.iterdir():
        match = _STAGING_NAME_RE.fullmatch(candidate.name)
        if match is None:
            continue
        try:
            expected = os.lstat(candidate)
            if not _owned_staging_tree(candidate):
                continue
            generation_id = match.group("generation")
            if not _staging_has_owned_proof(spec, candidate, generation_id):
                continue
            current = os.lstat(candidate)
            if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
                continue
            shutil.rmtree(candidate)
            _fsync_directory(spec.namespace)
            deleted.append(candidate.name)
        except OSError:
            logger.warning(
                "LCM periodic backup could not clean abandoned staging %s",
                candidate,
                exc_info=True,
            )
    return deleted


def _call_fault(fault: FaultHook | None, stage: str) -> None:
    if fault is not None:
        fault(stage)


def _publish_pointer(
    spec: PeriodicBackupSpec,
    generation_id: str,
    completed_at: str,
    *,
    fault: FaultHook | None,
) -> None:
    pointer = {
        "schema": POINTER_SCHEMA,
        "source_identity": _identity_payload(spec),
        "generation_id": generation_id,
        "completed_at": completed_at,
    }
    tmp = spec.namespace / f".{_POINTER_NAME}.{uuid.uuid4().hex}.tmp"
    renamed = False
    try:
        _call_fault(fault, "pointer_write")
        _write_json_exclusive(tmp, pointer)
        _call_fault(fault, "pointer_rename")
        os.replace(tmp, spec.namespace / _POINTER_NAME)
        renamed = True
        _call_fault(fault, "pointer_fsync")
        _fsync_directory(spec.namespace)
    except Exception as exc:
        raise PointerPublicationError(str(exc), renamed=renamed) from exc
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _owned_generations(
    spec: PeriodicBackupSpec,
    *,
    cancel: threading.Event | None,
) -> list[tuple[datetime, Path]]:
    owned: list[tuple[datetime, Path]] = []
    for candidate in spec.namespace.iterdir():
        if not candidate.name.startswith(_GENERATION_PREFIX) or candidate.name.endswith(".partial"):
            continue
        try:
            observed = os.lstat(candidate)
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                continue
            manifest = _verify_generation(spec, candidate, cancel=cancel)
            completed = _parse_utc(manifest.get("completed_at"))
        except PeriodicBackupCancelled:
            raise
        except (OSError, PeriodicBackupError):
            continue
        owned.append((completed, candidate))
    return sorted(owned, key=lambda item: (item[0], item[1].name), reverse=True)


def _apply_retention(
    spec: PeriodicBackupSpec,
    *,
    fault: FaultHook | None,
    cancel: threading.Event | None,
) -> tuple[list[str], str | None]:
    verified = _read_verified_pointer(spec, cancel=cancel)
    if verified is None:
        raise PeriodicBackupError("retention requires a verified latest-good target")
    protected = verified[0].resolve(strict=True)
    generations = _owned_generations(spec, cancel=cancel)
    keep: set[Path] = {path.resolve(strict=True) for _, path in generations[: spec.keep_last]}
    keep.add(protected)
    deleted: list[str] = []
    for _completed, candidate in reversed(generations):
        resolved = candidate.resolve(strict=True)
        if resolved in keep:
            continue
        try:
            expected = os.lstat(candidate)
            _verify_generation(spec, candidate, cancel=cancel)
            current = os.lstat(candidate)
            if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
                raise PeriodicBackupError("retention candidate changed before deletion")
            _call_fault(fault, f"retention_delete:{candidate.name}")
            shutil.rmtree(candidate)
            _fsync_directory(spec.namespace)
            deleted.append(candidate.name)
        except PeriodicBackupCancelled:
            raise
        except (OSError, PeriodicBackupError, PeriodicBackupUnsupported) as exc:
            return deleted, str(exc)
    return deleted, None


def run_periodic_backup(
    spec: PeriodicBackupSpec,
    *,
    due_only: bool = True,
    now: datetime | None = None,
    cancel: threading.Event | None = None,
    _fault: FaultHook | None = None,
    _force_due_if_generation: str | None = None,
    _publication_gate: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Attempt one locked backup transaction without touching the live DB.

    The only writes are under ``spec.namespace``.  No code path restores,
    renames, replaces, truncates, or deletes ``spec.source_db`` or the source
    payload directory.
    """
    started = now or _utc_now()
    partial: Path | None = None
    final: Path | None = None
    pointer_renamed = False
    try:
        if cancel is not None and cancel.is_set():
            return {"ok": False, "status": "cancelled"}
        _prepare_namespace(spec)
        lock = _NamespaceLock(spec.namespace)
        if not lock.acquire():
            return {"ok": False, "status": "deferred_busy", "namespace": spec.namespace}
        with lock:
            _call_fault(_fault, "locked")
            # Existing metadata is an ownership boundary.  Never overwrite a
            # corrupt or foreign pointer and then treat that as recovery.
            verified = None
            if (spec.namespace / _POINTER_NAME).exists():
                verified = _read_verified_pointer(spec, cancel=cancel)
            _cleanup_abandoned_staging(spec)
            current_generation_id = verified[0].name if verified is not None else None
            due_in = _seconds_from_verified_pointer(spec, verified, now=started)
            force_monotonic_due = (
                _force_due_if_generation is not None
                and current_generation_id == _force_due_if_generation
            )
            if due_only and due_in > 0 and not force_monotonic_due:
                return {
                    "ok": True,
                    "status": "noop_not_due",
                    "namespace": spec.namespace,
                    "generation_id": current_generation_id,
                }
            if cancel is not None and cancel.is_set():
                return {"ok": False, "status": "cancelled", "namespace": spec.namespace}

            generation_id = f"{_GENERATION_PREFIX}{started.strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:12]}"
            partial = spec.namespace / f"{generation_id}.partial"
            final = spec.namespace / generation_id
            _private_directory(partial)
            _write_json_exclusive(
                partial / _STAGING_OWNER_NAME,
                {
                    "schema": _STAGING_SCHEMA,
                    "source_identity": _identity_payload(spec),
                    "generation_id": generation_id,
                    "creator_pid": os.getpid(),
                },
            )
            _fsync_directory(partial)
            _fsync_directory(spec.namespace)
            payload_dir = partial / "payloads"
            _private_directory(payload_dir)

            _call_fault(_fault, "snapshot")
            staged_db = partial / "lcm.sqlite3"
            _snapshot_database(spec, staged_db, cancel=cancel)
            _call_fault(_fault, "integrity")
            _integrity_check(staged_db, cancel=cancel)

            references = _enumerate_recovery_refs(staged_db, cancel=cancel)
            payload_entries: list[dict[str, Any]] = []
            for ref in sorted({reference.ref for reference in references}):
                _call_fault(_fault, f"payload:{ref}")
                payload_entries.append(
                    _copy_payload(
                        spec,
                        ref,
                        payload_dir / ref,
                        cancel=cancel,
                    )
                )
            _fsync_directory(payload_dir)
            _verify_payload_recovery(payload_dir, references, cancel=cancel)

            database_size, database_hash = _sha256_file(staged_db, cancel=cancel)
            completed_at = _utc_text(_utc_now())
            manifest = {
                "schema": BUNDLE_SCHEMA,
                "generation_id": generation_id,
                "source_identity": _identity_payload(spec),
                "source_version": {
                    "format": SOURCE_IDENTITY_VERSION,
                    "implementation": "hermes-lcm-periodic-backup",
                },
                "started_at": _utc_text(started),
                "completed_at": completed_at,
                "database": {
                    "basename": "lcm.sqlite3",
                    "size": database_size,
                    "sha256": database_hash,
                    "integrity_check": "ok",
                },
                "payloads": payload_entries,
            }
            _call_fault(_fault, "manifest")
            _write_json_exclusive(partial / "manifest.json", manifest)
            _call_fault(_fault, "stage_fsync")
            _fsync_file(staged_db)
            for entry in payload_entries:
                _fsync_file(payload_dir / str(entry["basename"]))
            _fsync_directory(payload_dir)
            _fsync_directory(partial)
            _verify_generation(
                spec,
                partial,
                expected_generation_id=generation_id,
                cancel=cancel,
            )

            # Revalidate staged bytes while the source publication gate excludes
            # a concurrent suspension/rebind through pointer replacement.  A
            # boolean preflight is not enough: releasing the registry lock
            # before rename lets a stale-root transaction publish after the
            # source has been suspended.
            _call_fault(_fault, "before_final_validation")
            gate = _publication_gate() if _publication_gate is not None else nullcontext(True)
            with gate as publication_allowed:
                if not publication_allowed:
                    raise PeriodicBackupCancelled(
                        "periodic backup publication was suspended before rename"
                    )
                _verify_generation(
                    spec,
                    partial,
                    expected_generation_id=generation_id,
                    cancel=cancel,
                )
                (partial / _STAGING_OWNER_NAME).unlink()
                _fsync_directory(partial)
                _call_fault(_fault, "final_rename")
                os.rename(partial, final)
                partial = None
                _call_fault(_fault, "final_fsync")
                _fsync_directory(spec.namespace)

                try:
                    _publish_pointer(
                        spec,
                        generation_id,
                        completed_at,
                        fault=_fault,
                    )
                    pointer_renamed = True
                except PointerPublicationError as exc:
                    # If os.replace succeeded but namespace fsync failed, pointer bytes
                    # may already name the candidate. Preserve old and new bundles,
                    # skip retention, and let restart reverify rather than pretending
                    # rollback can restore pointer durability.
                    return {
                        "ok": False,
                        "status": "published_pointer_failed",
                        "generation": final,
                        "generation_id": generation_id,
                        "pointer_durability": "uncertain" if exc.renamed else "unchanged",
                        "pointer_renamed": exc.renamed,
                        "error": str(exc),
                    }

                _call_fault(_fault, "retention")
                deleted, retention_error = _apply_retention(
                    spec,
                    fault=_fault,
                    cancel=cancel,
                )
                if retention_error is not None:
                    logger.warning(
                        "LCM periodic backup retention stopped after deletion failure "
                        "source=%s error=%s",
                        spec.source_db,
                        retention_error,
                    )
                    return {
                        "ok": True,
                        "status": "ok_retention_failed",
                        "generation": final,
                        "generation_id": generation_id,
                        "deleted": deleted,
                        "retention_error": retention_error,
                    }
                return {
                    "ok": True,
                    "status": "ok",
                    "generation": final,
                    "generation_id": generation_id,
                    "deleted": deleted,
                    "payload_count": len(payload_entries),
                }
    except PeriodicBackupUnsupported as exc:
        return {"ok": False, "status": "unsupported", "error": str(exc)}
    except PeriodicBackupCancelled as exc:
        return {"ok": False, "status": "cancelled", "error": str(exc)}
    except Exception as exc:
        return {
            "ok": False,
            "status": "failed",
            "error": str(exc),
            "published": final is not None and final.exists(),
            "pointer_renamed": pointer_renamed,
        }
    finally:
        if partial is not None:
            _cleanup_partial(partial)


class _Scheduler:
    """The worker is deliberately ignorant of engine/profile ownership."""

    def __init__(self, source: "BackupSource | PeriodicBackupSpec"):
        if isinstance(source, PeriodicBackupSpec):
            class _StandaloneSource:
                spec = source

                @staticmethod
                @contextmanager
                def publication_gate(_expected_epoch: int):
                    yield True

            self.source = _StandaloneSource()
            self.spec = source
            autostart = True
        else:
            self.source = source
            self.spec = source.spec
            autostart = False
        self.cancel = threading.Event()
        self.condition = threading.Condition()
        self.thread = threading.Thread(
            target=self._run,
            name=f"lcm-periodic-backup-{self.spec.source_identity[:12]}",
            daemon=True,
        )
        if autostart:
            self.start()

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        retry_delay = 0.0
        uncertain_generation_id: str | None = None
        try:
            due_in, observed_generation = _verified_due_state(
                self.spec,
                cancel=self.cancel,
            )
        except Exception:
            due_in, observed_generation = 0.0, None
        next_due_monotonic = time.monotonic() + due_in
        while not self.cancel.is_set():
            retrying_failed_transaction = retry_delay > 0
            wait_for = (
                retry_delay
                if retrying_failed_transaction
                else max(0.0, next_due_monotonic - time.monotonic())
            )
            if wait_for > 0:
                with self.condition:
                    self.condition.wait_for(self.cancel.is_set, timeout=wait_for)
                if self.cancel.is_set():
                    return
            monotonic_due = time.monotonic() >= next_due_monotonic
            # A post-rename fsync failure may retry early only while the pointer
            # still names that exact uncertain generation.  The transaction
            # compares this identity under the namespace flock, so a verified
            # generation from another process suppresses redundant publication.
            force_generation_id = uncertain_generation_id
            if force_generation_id is None and monotonic_due:
                force_generation_id = observed_generation
            with _REGISTRY_LOCK:
                publication_epoch = int(getattr(self.source, "publication_epoch", 0))
            try:
                result = run_periodic_backup(
                    self.spec,
                    due_only=True,
                    cancel=self.cancel,
                    _force_due_if_generation=force_generation_id,
                    _publication_gate=lambda: self.source.publication_gate(publication_epoch),
                )
            except Exception as exc:
                result = {"ok": False, "status": "failed", "error": str(exc)}
            status = str(result.get("status") or "failed")
            if status in {"ok", "ok_retention_failed"}:
                observed_generation = str(result.get("generation_id") or "") or None
                next_due_monotonic = time.monotonic() + self.spec.interval_seconds
                retry_delay = 0.0
                uncertain_generation_id = None
            elif status == "noop_not_due":
                try:
                    due_in, verified_generation = _verified_due_state(
                        self.spec,
                        cancel=self.cancel,
                    )
                except Exception:
                    due_in, verified_generation = 0.0, None
                observed_generation = (
                    str(result.get("generation_id") or "")
                    or verified_generation
                )
                next_due_monotonic = time.monotonic() + due_in
                retry_delay = 0.0
                uncertain_generation_id = None
            elif status == "cancelled":
                return
            else:
                retry_delay = min(
                    _MAX_FAILURE_BACKOFF_SECONDS,
                    max(1.0, min(60.0, self.spec.interval_seconds / 4.0)),
                )
                if status == "published_pointer_failed" and result.get("pointer_renamed"):
                    candidate = str(result.get("generation_id") or "")
                    if candidate:
                        uncertain_generation_id = candidate
                logger.warning(
                    "LCM periodic backup deferred or failed status=%s source=%s error=%s",
                    status,
                    self.spec.source_db,
                    result.get("error", ""),
                )

    def stop(self) -> bool:
        self.cancel.set()
        with self.condition:
            self.condition.notify_all()
        self.thread.join(timeout=_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS)
        return not self.thread.is_alive()


class _MissingRootRetryController:
    """Bounded admission retry for a configured root that does not yet exist."""

    def __init__(self, source: "BackupSource"):
        self.source = source
        self.cancel = threading.Event()
        self.condition = threading.Condition()
        self.thread = threading.Thread(
            target=self._run,
            name=f"lcm-periodic-backup-retry-{source.spec.source_identity[:12]}",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        # Use the configured cadence, but cap it so enabled scheduling cannot be
        # silently inert for hours after an operator restores the root.
        wait_for = min(60.0, max(0.01, self.source.spec.interval_seconds))
        try:
            while not self.cancel.is_set():
                with self.condition:
                    self.condition.wait_for(self.cancel.is_set, timeout=wait_for)
                if self.cancel.is_set():
                    return
                if _retry_missing_root(self.source.key, self.source):
                    return
        finally:
            with _REGISTRY_LOCK:
                if self.source.retry_controller is self:
                    self.source.retry_controller = None
                    _drop_if_unowned_locked(self.source)

    def stop(self) -> None:
        self.cancel.set()
        with self.condition:
            self.condition.notify_all()


@dataclass
class BackupSource:
    """Single process-local source of truth for a canonical SQLite database."""

    key: str
    spec: PeriodicBackupSpec
    approved_root: PayloadRootBinding | None
    state: str = "ACTIVE"
    reason: str = ""
    publication_epoch: int = 0
    scheduler: _Scheduler | None = None
    retry_controller: _MissingRootRetryController | None = None
    handoff_thread: threading.Thread | None = None
    active_owners: set[object] = None  # type: ignore[assignment]
    pending_owners: set[object] = None  # type: ignore[assignment]
    suspended_owners: set[object] = None  # type: ignore[assignment]
    owner_bindings: dict[object, PayloadRootBinding | None] = None  # type: ignore[assignment]
    registrations: dict[object, PeriodicBackupRegistration] = None  # type: ignore[assignment]
    owner_records: dict[object, OwnerRecord] = None  # type: ignore[assignment]
    canonical_policy: PolicyFingerprint | None = None
    approved_root_history: tuple[PayloadRootBinding, ...] = ()
    readmission: dict[str, Any] | None = None
    # Once a distinct root has made history ambiguous, an optional scheduling
    # failure must not erase the last approved root and let ordinary admission
    # create a fresh ACTIVE source.  This process-local tombstone is cleared
    # only by the explicit historical-reference readmission path.
    readmission_required: bool = False
    # A successful ownerless readmission must retain the approved authority
    # until an ordinary compatible lease attaches. Otherwise a status query
    # could drop it and let a later incompatible root create a fresh source.
    readmission_armed: bool = False
    # A previously admitted pathname disappeared. A new inode at that path
    # must pass retained-history readmission before any owner can publish.
    missing_root_replacement: bool = False
    conflict_count: int = 0
    last_conflict_reason: str = ""

    def __post_init__(self) -> None:
        self.active_owners = set()
        self.pending_owners = set()
        self.suspended_owners = set()
        self.owner_bindings = {}
        self.registrations = {}
        self.owner_records = {}
        if self.canonical_policy is None:
            self.canonical_policy = _policy_fingerprint(self.spec)
        if self.approved_root is not None and not self.approved_root_history:
            self.approved_root_history = (self.approved_root,)

    @property
    def thread(self) -> threading.Thread | None:
        return self.scheduler.thread if self.scheduler is not None else None

    @property
    def cancel(self) -> threading.Event:
        return self.scheduler.cancel if self.scheduler is not None else threading.Event()

    @property
    def owners(self) -> set[object]:
        return self.active_owners

    @contextmanager
    def publication_gate(self, expected_epoch: int):
        with _REGISTRY_LOCK:
            binding = self.spec.payload_root_binding
            try:
                root_matches = (
                    binding is not None
                    and self.approved_root is not None
                    and binding == self.approved_root
                    and binding.device != 0
                    and binding.inode != 0
                )
                if root_matches and binding is not None:
                    root_matches = _payload_root_binding(binding.path) == binding
            except (OSError, PeriodicBackupError):
                root_matches = False
            if not root_matches and self.state == "ACTIVE":
                _suspend_source_locked(self, "payload_root_identity_changed")
            yield (
                self.state == "ACTIVE"
                and self.publication_epoch == expected_epoch
                and self.scheduler is not None
                and not self.scheduler.cancel.is_set()
                and root_matches
            )

    def status(self) -> dict[str, Any]:
        worker = self.scheduler.thread if self.scheduler is not None else None
        retry = self.retry_controller.thread if self.retry_controller is not None else None
        handoff = self.handoff_thread
        policy = self.canonical_policy
        assert policy is not None
        return {
            "source_key": self.key,
            "state": self.state,
            "reason": self.reason,
            "publication_epoch": self.publication_epoch,
            "approved_root": str(self.approved_root.path) if self.approved_root is not None else "",
            "approved_root_identity": (
                (self.approved_root.device, self.approved_root.inode)
                if self.approved_root is not None
                else None
            ),
            "expected_root": str(self.spec.payload_root),
            "destination": str(self.spec.destination_root),
            "interval_seconds": self.spec.interval_seconds,
            "keep_last": self.spec.keep_last,
            "canonical_policy": {
                "destination": str(policy.destination_root),
                "interval_seconds": policy.interval_seconds,
                "keep_last": policy.keep_last,
                "expected_root": str(policy.expected_root),
            },
            "approved_root_history": [
                {
                    "path": str(binding.path),
                    "device": binding.device,
                    "inode": binding.inode,
                }
                for binding in self.approved_root_history
            ],
            "active_leases": len(self.active_owners),
            "pending_leases": len(self.pending_owners),
            "suspended_leases": len(self.suspended_owners),
            "worker_alive": bool(worker and worker.is_alive()),
            "worker_count": int(bool(worker and worker.is_alive())),
            "retry_controller_alive": bool(retry and retry.is_alive()),
            "retry_controller_count": int(bool(retry and retry.is_alive())),
            "handoff_alive": bool(handoff and handoff.is_alive()),
            "conflict_count": self.conflict_count,
            "last_conflict_reason": self.last_conflict_reason,
            "readmission": dict(self.readmission or {}),
            "readmission_required": self.readmission_required,
            "readmission_armed": self.readmission_armed,
        }


_REGISTRY_LOCK = threading.RLock()
_SCHEDULERS: dict[str, BackupSource] = {}


def _registration(key: str, owner: object, state: str, reason: str = "") -> PeriodicBackupRegistration:
    return PeriodicBackupRegistration(
        key,
        owner,
        state == "active",
        reason,
        state,
        reason,
    )


def _set_registration_state(
    source: BackupSource,
    owner: object,
    state: str,
    reason: str = "",
) -> PeriodicBackupRegistration:
    registration = source.registrations.get(owner)
    if registration is None:
        registration = _registration(source.key, owner, state, reason)
        source.registrations[owner] = registration
    else:
        registration.active = state == "active"
        registration.error = reason
        registration.state = state
        registration.reason = reason
    return registration


def _place_owner_locked(
    source: BackupSource,
    owner: object,
    binding: PayloadRootBinding | None,
    state: str,
    reason: str = "",
    *,
    policy: PolicyFingerprint | None = None,
) -> PeriodicBackupRegistration:
    source.active_owners.discard(owner)
    source.pending_owners.discard(owner)
    source.suspended_owners.discard(owner)
    source.owner_bindings[owner] = binding
    if state == "active":
        source.active_owners.add(owner)
    elif state == "pending":
        source.pending_owners.add(owner)
    elif state == "suspended":
        source.suspended_owners.add(owner)
    registration = _set_registration_state(source, owner, state, reason)
    record = source.owner_records.get(owner)
    if record is None:
        if policy is None or policy != source.canonical_policy:
            raise AssertionError("owner placement requires the canonical admitted policy")
        record = OwnerRecord(
            owner,
            policy,
            binding,
            source.publication_epoch,
            state,
            registration,
        )
    else:
        record = replace(record, state=state)
    source.owner_records[owner] = record
    return registration


def _forget_owner_locked(source: BackupSource, owner: object) -> None:
    source.active_owners.discard(owner)
    source.pending_owners.discard(owner)
    source.suspended_owners.discard(owner)
    source.owner_bindings.pop(owner, None)
    source.registrations.pop(owner, None)
    source.owner_records.pop(owner, None)


def _fail_source_locked(source: BackupSource, reason: str) -> None:
    """Fail optional scheduling without leaving a lease eligible or stale."""
    source.state = "ERROR"
    source.reason = reason
    source.publication_epoch += 1
    affected = set(source.active_owners) | set(source.pending_owners) | set(source.suspended_owners)
    for owner in affected:
        _set_registration_state(source, owner, "error", reason)
    source.active_owners.clear()
    source.pending_owners.clear()
    source.suspended_owners.clear()
    source.owner_bindings.clear()
    source.registrations.clear()
    source.owner_records.clear()


def _start_worker_locked(source: BackupSource) -> str:
    worker = _Scheduler(source)
    source.scheduler = worker
    try:
        worker.start()
    except RuntimeError as exc:
        source.scheduler = None
        reason = f"periodic_worker_start_failed:{exc}"
        _fail_source_locked(source, reason)
        return reason
    return ""


def _start_retry_controller_locked(source: BackupSource) -> str:
    retry = source.retry_controller
    if retry is not None and retry.thread.is_alive():
        return ""
    retry = _MissingRootRetryController(source)
    source.retry_controller = retry
    try:
        retry.start()
    except RuntimeError as exc:
        source.retry_controller = None
        reason = f"periodic_retry_controller_start_failed:{exc}"
        _fail_source_locked(source, reason)
        return reason
    return ""


def _policy_fingerprint(spec: PeriodicBackupSpec) -> PolicyFingerprint:
    return PolicyFingerprint(
        destination_root=spec.destination_root,
        interval_seconds=spec.interval_seconds,
        keep_last=spec.keep_last,
        expected_root=spec.payload_root,
    )


def _policy_conflict_fields(
    current: PolicyFingerprint,
    candidate: PolicyFingerprint,
) -> list[str]:
    fields: list[str] = []
    if current.destination_root != candidate.destination_root:
        fields.append("destination")
    if current.interval_seconds != candidate.interval_seconds:
        fields.append("interval")
    if current.keep_last != candidate.keep_last:
        fields.append("retention")
    return fields


def _admitted_registration_locked(
    engine,
    source: BackupSource,
) -> PeriodicBackupRegistration | None:
    registration = getattr(engine, "_periodic_backup_registration", None)
    visited: set[int] = set()
    while isinstance(registration, PeriodicBackupRegistration) and id(registration) not in visited:
        visited.add(id(registration))
        if (
            registration.source_key == source.key
            and registration.owner in source.owner_records
        ):
            return source.registrations.get(registration.owner, registration)
        registration = registration.retained_registration
    return None


def _retain_admitted_handle_locked(
    registration: PeriodicBackupRegistration,
    engine,
    source: BackupSource,
) -> PeriodicBackupRegistration:
    registration.retained_registration = _admitted_registration_locked(engine, source)
    return registration


def _suspended_observation_locked(
    source: BackupSource,
    owner: object,
    engine,
) -> PeriodicBackupRegistration:
    return _retain_admitted_handle_locked(
        _registration(
            source.key,
            owner,
            "suspended",
            source.reason or "payload_root_ambiguous",
        ),
        engine,
        source,
    )


def _conflict_registration_locked(
    source: BackupSource,
    owner: object,
    fields: list[str],
    engine,
) -> PeriodicBackupRegistration:
    reason = f"periodic_scheduler_spec_conflict:{'+'.join(fields)}"
    source.conflict_count += 1
    source.last_conflict_reason = reason
    registration = _registration(source.key, owner, "conflict", reason)
    return _retain_admitted_handle_locked(registration, engine, source)


def _retry_missing_root(key: str, source: BackupSource) -> bool:
    try:
        binding = _payload_root_binding(source.spec.payload_root)
    except (OSError, PeriodicBackupError):
        return False
    with _REGISTRY_LOCK:
        if (
            _SCHEDULERS.get(key) is not source
            or source.state != "SUSPENDED"
            or source.reason != "payload_root_missing"
        ):
            return True
        worker = source.scheduler
        if worker is not None and worker.thread.is_alive():
            return False
        if (
            source.missing_root_replacement
            and source.approved_root is not None
            and binding != source.approved_root
        ):
            # Recreating a pathname does not recreate its authority. Keep the
            # retry controller bounded and non-publishing until retained
            # references are checked through resume_backup_source().
            return False
        source.approved_root = binding
        if binding not in source.approved_root_history:
            source.approved_root_history = (*source.approved_root_history, binding)
        source.spec = replace(source.spec, payload_root_binding=binding)
        for owner in set(source.suspended_owners):
            record = source.owner_records.get(owner)
            if record is not None and record.admitted_policy_fingerprint == source.canonical_policy:
                _place_owner_locked(source, owner, binding, "active")
        source.state = "ACTIVE"
        source.reason = ""
        source.publication_epoch += 1
        source.readmission_required = False
        source.missing_root_replacement = False
        error = _start_worker_locked(source)
        if error:
            _drop_if_unowned_locked(source)
        retry = source.retry_controller
        if retry is not None:
            retry.stop()
        return True


def _drop_if_unowned_locked(source: BackupSource) -> None:
    worker = source.scheduler
    if worker is not None and not worker.thread.is_alive():
        source.scheduler = None
    handoff = source.handoff_thread
    if handoff is not None and not handoff.is_alive():
        source.handoff_thread = None
    retry = source.retry_controller
    if retry is not None and not retry.thread.is_alive():
        source.retry_controller = None
    if (
        source.readmission_required
        and source.state == "ERROR"
        and source.scheduler is None
        and source.handoff_thread is None
    ):
        source.state = "SUSPENDED"
        source.reason = f"historical_readmission_required:{source.reason}"
    if source.active_owners or source.pending_owners or source.suspended_owners:
        return
    retry = source.retry_controller
    if retry is not None and retry.thread.is_alive():
        retry.stop()
        return
    worker = source.scheduler
    if worker is not None and worker.thread.is_alive():
        return
    handoff = source.handoff_thread
    if handoff is not None and handoff.is_alive():
        return
    # A root-ambiguity tombstone is authoritative safety state, not a stale
    # scheduler entry.  Recheck after the last owner and worker are gone so
    # references written while publication was suspended cannot be missed.
    if source.readmission_required:
        if _source_has_root_dependent_history(source):
            return
        source.readmission_required = False
    if source.readmission_armed:
        if _source_has_root_dependent_history(source):
            return
        source.readmission_armed = False
    _SCHEDULERS.pop(source.key, None)


def _complete_handoff(key: str, source: BackupSource, worker: _Scheduler) -> None:
    worker.thread.join()
    with _REGISTRY_LOCK:
        if _SCHEDULERS.get(key) is not source or source.scheduler is not worker:
            return
        source.scheduler = None
        source.handoff_thread = None
        if source.state in {"SUSPENDED", "ERROR"}:
            _drop_if_unowned_locked(source)
            return
        retained = set(source.pending_owners)
        source.pending_owners.clear()
        if not retained:
            source.state = "ACTIVE"
            source.reason = ""
            _drop_if_unowned_locked(source)
            return
        for owner in retained:
            binding = source.owner_bindings.get(owner)
            if binding is not None:
                _place_owner_locked(source, owner, binding, "active")
        source.state = "ACTIVE"
        source.reason = ""
        source.publication_epoch += 1
        error = _start_worker_locked(source)
        if error:
            _drop_if_unowned_locked(source)


def _queue_handoff_locked(source: BackupSource) -> str:
    if source.handoff_thread is not None and source.handoff_thread.is_alive():
        return ""
    worker = source.scheduler
    if worker is None:
        return "periodic handoff has no stopping worker"
    watcher = threading.Thread(
        target=_complete_handoff,
        args=(source.key, source, worker),
        name=f"lcm-backup-handoff-{source.spec.source_identity[:12]}",
        daemon=True,
    )
    try:
        watcher.start()
    except RuntimeError as exc:
        source.handoff_thread = None
        reason = f"periodic_handoff_start_failed:{exc}"
        _fail_source_locked(source, reason)
        return reason
    source.handoff_thread = watcher
    return ""


def _source_has_root_dependent_history(source: BackupSource) -> bool:
    """Conservatively decide whether dropping root authority can lose history."""
    if (source.spec.namespace / _POINTER_NAME).exists():
        return True
    try:
        return bool(_snapshot_recovery_references(source.spec))
    except Exception:
        # Failure to prove the source has no root-dependent references is not
        # permission to forget the approved root.
        return True


def _suspend_source_locked(source: BackupSource, reason: str) -> str:
    owners = set(source.active_owners) | set(source.pending_owners) | set(source.suspended_owners)
    source.state = "SUSPENDED"
    source.reason = reason
    source.readmission_required = True
    source.readmission_armed = False
    source.missing_root_replacement = (
        reason == "payload_root_missing" and source.approved_root is not None
    )
    source.publication_epoch += 1
    for owner in owners:
        binding = source.owner_bindings.get(owner)
        if binding is not None:
            _place_owner_locked(source, owner, binding, "suspended", reason)
    if source.scheduler is not None:
        source.scheduler.cancel.set()
        with source.scheduler.condition:
            source.scheduler.condition.notify_all()
        # A suspended source never promotes a successor, but it still needs a
        # distinct waiter to observe the old worker's actual exit.  Clearing
        # ``source.scheduler`` from the worker's own finally block is too
        # early: the thread is still alive between that block and its real
        # termination, and readmission could start a second worker.
        if source.scheduler.thread.is_alive():
            error = _queue_handoff_locked(source)
            if error:
                logger.warning("LCM periodic backup suspension handoff failed closed: %s", error)
                return error
    return ""


def acquire_backup_lease(engine) -> PeriodicBackupRegistration:
    owner = object()
    if getattr(engine._config, "periodic_backup_enabled", False) is False:
        return _registration("", owner, "disabled")
    try:
        spec = build_periodic_backup_spec(engine, allow_missing_payload_root=True)
        binding = spec.payload_root_binding
        requested_policy = _policy_fingerprint(spec)
    except Exception as exc:
        logger.warning("LCM periodic backup registration failed closed: %s", exc)
        return _registration("", owner, "error", str(exc))
    key = str(spec.source_db)
    with _REGISTRY_LOCK:
        source = _SCHEDULERS.get(key)
        if source is not None and source.state == "ERROR":
            _drop_if_unowned_locked(source)
            source = _SCHEDULERS.get(key)
            if source is not None and source.state == "ERROR":
                canonical_policy = source.canonical_policy
                assert canonical_policy is not None
                conflicts = _policy_conflict_fields(canonical_policy, requested_policy)
                if conflicts:
                    return _conflict_registration_locked(
                        source, owner, conflicts, engine
                    )
                return _registration(key, owner, "error", source.reason)
        if source is None:
            if binding is None:
                source = BackupSource(
                    key,
                    spec,
                    None,
                    state="SUSPENDED",
                    reason="payload_root_missing",
                )
                registration = _place_owner_locked(
                    source,
                    owner,
                    None,
                    "suspended",
                    "payload_root_missing",
                    policy=requested_policy,
                )
                _SCHEDULERS[key] = source
                error = _start_retry_controller_locked(source)
                if error:
                    _drop_if_unowned_locked(source)
                return registration
            source = BackupSource(key, spec, binding)
            registration = _place_owner_locked(
                source,
                owner,
                binding,
                "active",
                policy=requested_policy,
            )
            _SCHEDULERS[key] = source
            error = _start_worker_locked(source)
            if error:
                _drop_if_unowned_locked(source)
            return registration

        canonical_policy = source.canonical_policy
        assert canonical_policy is not None
        conflicts = _policy_conflict_fields(canonical_policy, requested_policy)
        if conflicts:
            # A mismatch has presentation authority only. Root observation,
            # suspension, retry, and admission state are intentionally untouched.
            return _conflict_registration_locked(source, owner, conflicts, engine)

        existing_registration = _admitted_registration_locked(engine, source)
        if (
            binding is None
            and spec.payload_root == source.spec.payload_root
            and not (
                source.state == "SUSPENDED"
                and source.reason
                not in {"payload_root_missing", "payload_root_identity_changed"}
            )
        ):
            error = _suspend_source_locked(source, "payload_root_missing")
            if error:
                _drop_if_unowned_locked(source)
                return _registration(key, owner, "error", error)
            error = _start_retry_controller_locked(source)
            if error:
                _drop_if_unowned_locked(source)
                return _registration(key, owner, "error", error)
            return existing_registration or _suspended_observation_locked(
                source, owner, engine
            )
        # Root authority is the older, stronger N1 invariant. A configured-DB
        # home rebind that changes both root and destination is ambiguity, not a
        # policy-only conflict, and must suspend every existing owner.
        if source.state == "SUSPENDED" and source.reason != "payload_root_missing":
            return existing_registration or _suspended_observation_locked(
                source, owner, engine
            )
        if (
            binding is not None
            and source.approved_root is not None
            and binding != source.approved_root
        ):
            error = _suspend_source_locked(source, "payload_root_ambiguous")
            if error:
                _drop_if_unowned_locked(source)
                return _registration(key, owner, "error", error)
            return existing_registration or _suspended_observation_locked(
                source, owner, engine
            )
        if spec.payload_root != source.spec.payload_root:
            error = _suspend_source_locked(source, "payload_root_ambiguous")
            if error:
                _drop_if_unowned_locked(source)
                return _registration(key, owner, "error", error)
            return existing_registration or _suspended_observation_locked(
                source, owner, engine
            )

        worker = source.scheduler
        if source.state == "SUSPENDED" and source.reason == "payload_root_missing":
            if binding is None:
                error = _start_retry_controller_locked(source)
                if error:
                    _drop_if_unowned_locked(source)
                return existing_registration or _suspended_observation_locked(
                    source, owner, engine
                )
            _retry_missing_root(key, source)
            if source.state == "ERROR":
                return _registration(key, owner, "error", source.reason)
            if existing_registration is not None:
                return source.registrations.get(
                    existing_registration.owner,
                    existing_registration,
                )
            return _suspended_observation_locked(source, owner, engine)
        if source.state == "SUSPENDED":
            return existing_registration or _suspended_observation_locked(
                source, owner, engine
            )
        if binding is None:
            error = _suspend_source_locked(source, "payload_root_missing")
            if error:
                _drop_if_unowned_locked(source)
                return _registration(key, owner, "error", error)
            error = _start_retry_controller_locked(source)
            if error:
                _drop_if_unowned_locked(source)
                return _registration(key, owner, "error", error)
            return existing_registration or _suspended_observation_locked(
                source, owner, engine
            )
        if binding != source.approved_root:
            error = _suspend_source_locked(source, "payload_root_ambiguous")
            if error:
                # The source has been transitioned to ERROR and every existing
                # lease has already been made ineligible.  Do not reinsert this
                # replacement owner as suspended: that would retain an ERROR
                # source after the old worker exits and misreport a failed
                # optional handoff allocation as a valid suspension.
                _drop_if_unowned_locked(source)
                return _registration(key, owner, "error", error)
            return existing_registration or _suspended_observation_locked(
                source, owner, engine
            )
        if existing_registration is not None:
            return existing_registration
        if worker is not None and worker.cancel.is_set() and worker.thread.is_alive():
            registration = _place_owner_locked(
                source,
                owner,
                binding,
                "pending",
                "waiting_for_stopping_worker",
                policy=requested_policy,
            )
            source.state = "PENDING"
            source.reason = "waiting_for_stopping_worker"
            error = _queue_handoff_locked(source)
            if error:
                _drop_if_unowned_locked(source)
            return registration
        if worker is None or not worker.thread.is_alive():
            registration = _place_owner_locked(
                source,
                owner,
                binding,
                "active",
                policy=requested_policy,
            )
            source.state = "ACTIVE"
            source.reason = ""
            consumes_readmission = source.readmission_armed
            error = _start_worker_locked(source)
            if error:
                _drop_if_unowned_locked(source)
            elif consumes_readmission:
                # Keep the approved root authority until a compatible worker
                # has actually started. Thread.start failure must not let a
                # later incompatible lease create a fresh source.
                source.readmission_armed = False
            return registration
        return _place_owner_locked(
            source,
            owner,
            binding,
            "active",
            policy=requested_policy,
        )


def register_periodic_backup(engine) -> PeriodicBackupRegistration:
    return acquire_backup_lease(engine)


def suspend_periodic_backup_source(
    registration: PeriodicBackupRegistration | None,
    *,
    reason: str = "payload_root_ambiguous",
) -> PeriodicBackupRegistration | None:
    """Fail closed without dropping the sole prior root authority.

    A configured-database home rebind can discover an invalid replacement root
    before ordinary admission obtains a candidate binding.  The old lease must
    remain attached to the canonical source so a later valid retry compares
    against its history instead of creating a fresh source for the new root.
    """
    if registration is None or not registration.source_key:
        return registration
    with _REGISTRY_LOCK:
        source = _SCHEDULERS.get(registration.source_key)
        if source is None or registration.owner not in source.registrations:
            return None
        _suspend_source_locked(source, reason)
        return source.registrations.get(registration.owner, registration)


def release_backup_lease(registration: PeriodicBackupRegistration | None) -> bool:
    if registration is None or not registration.source_key:
        return True
    if registration.retained_registration is not None:
        retained = registration.retained_registration
        registration.retained_registration = None
        return release_backup_lease(retained)
    with _REGISTRY_LOCK:
        source = _SCHEDULERS.get(registration.source_key)
        if source is None:
            return True
        if registration.owner not in source.active_owners:
            _forget_owner_locked(source, registration.owner)
            _drop_if_unowned_locked(source)
            return True
        _forget_owner_locked(source, registration.owner)
        if source.active_owners:
            return True
        worker = source.scheduler
        if worker is None:
            _drop_if_unowned_locked(source)
            return True
        source.state = "STOPPING"
        source.reason = "last_active_lease_released"
        source.publication_epoch += 1
        stopped = worker.stop()
        if stopped:
            source.scheduler = None
            if source.pending_owners:
                source.state = "PENDING"
                retained = set(source.pending_owners)
                source.pending_owners.clear()
                for owner in retained:
                    binding = source.owner_bindings.get(owner)
                    if binding is not None:
                        _place_owner_locked(source, owner, binding, "active")
                source.state = "ACTIVE"
                source.reason = ""
                error = _start_worker_locked(source)
                if not error:
                    return True
                _drop_if_unowned_locked(source)
            else:
                _drop_if_unowned_locked(source)
            return True
        source.state = "PENDING" if source.pending_owners else "STOPPING"
        source.reason = "waiting_for_stopping_worker"
        error = _queue_handoff_locked(source)
        if error:
            logger.warning("LCM periodic backup handoff failed closed: %s", error)
        return False


def unregister_periodic_backup(registration: PeriodicBackupRegistration | None) -> bool:
    return release_backup_lease(registration)


def resume_backup_source(
    source_key: str,
    candidate_binding: PayloadRootBinding | Path,
) -> PeriodicBackupRegistration:
    """Explicitly re-admit a suspended source after safe reference checks."""
    with _REGISTRY_LOCK:
        source = _SCHEDULERS.get(source_key)
        if source is None:
            return _registration(source_key, object(), "error", "unknown_backup_source")
        # Readmission is the approved lifecycle recovery path, so it must reap
        # a worker/handoff that has actually exited before checking quiescence.
        # In particular, do not require a status query or ordinary acquisition
        # to reconcile an ERROR root-authority tombstone to SUSPENDED first.
        _drop_if_unowned_locked(source)
        source = _SCHEDULERS.get(source_key)
        if source is None:
            return _registration(source_key, object(), "error", "unknown_backup_source")
        if source.state in {"ACTIVE", "ERROR"} and source.readmission_armed:
            try:
                binding = (
                    candidate_binding
                    if isinstance(candidate_binding, PayloadRootBinding)
                    else _payload_root_binding(candidate_binding)
                )
            except Exception as exc:
                return _registration(source_key, object(), "error", str(exc))
            if binding == source.approved_root:
                # Historical validation already succeeded. Re-arm ordinary
                # compatible acquisition while retaining authority until its
                # replacement worker starts successfully.
                source.state = "ACTIVE"
                source.reason = ""
                return _registration(source_key, object(), "active")
        if source.state != "SUSPENDED" or (source.scheduler and source.scheduler.thread.is_alive()):
            return _registration(source_key, object(), "error", "source_not_quiescent_suspended")
        try:
            binding = candidate_binding if isinstance(candidate_binding, PayloadRootBinding) else _payload_root_binding(candidate_binding)
            missing_root_replacement = (
                source.missing_root_replacement
                and source.approved_root is not None
                and binding.path == source.approved_root.path
            )
            candidate = replace(
                source.spec,
                payload_root=binding.path,
                payload_root_binding=binding,
            )
            references = _snapshot_recovery_references(candidate)
            _verify_readmission_payloads(binding, references)
            if (candidate.namespace / _POINTER_NAME).exists():
                verified = _read_verified_pointer(candidate)
                if verified is None:
                    raise PeriodicBackupError("latest-good disappeared during readmission")
                generation, manifest = verified
                retained_references = _enumerate_recovery_refs(
                    generation / "lcm.sqlite3", cancel=None
                )
                payloads = manifest.get("payloads")
                if not isinstance(payloads, list):
                    raise PeriodicBackupError("retained generation manifest content is invalid")
                _verify_readmission_payloads(
                    binding,
                    retained_references,
                    manifest_payloads=payloads,
                )
        except Exception as exc:
            source.reason = f"historical_reference_readmission_failed:{exc}"
            source.readmission = {
                "ok": False,
                "reason": source.reason,
                "candidate_root": str(getattr(candidate_binding, "path", candidate_binding)),
            }
            return _registration(source_key, object(), "suspended", source.reason)
        source.approved_root = binding
        if binding not in source.approved_root_history:
            source.approved_root_history = (*source.approved_root_history, binding)
        source.spec = candidate
        source.state = "ACTIVE"
        source.reason = ""
        source.publication_epoch += 1
        source.readmission = {
            "ok": True,
            "candidate_root": str(binding.path),
            "candidate_root_identity": (binding.device, binding.inode),
            "snapshot_reference_count": len({reference.ref for reference in references}),
        }
        compatible_owners = {
            owner
            for owner in source.suspended_owners
            if (
                (record := source.owner_records.get(owner)) is not None
                and record.admitted_policy_fingerprint == source.canonical_policy
                and (
                    record.admitted_root_binding is None
                    or record.admitted_root_binding in source.approved_root_history
                )
                and (
                    source.readmission_required
                    or missing_root_replacement
                    or source.owner_bindings.get(owner) == binding
                )
            )
        }
        retained_records = {
            owner: source.owner_records[owner]
            for owner in compatible_owners
        }
        for owner in compatible_owners:
            source.owner_bindings[owner] = binding
            _place_owner_locked(source, owner, binding, "active")
        # Historical authority may be consumed only after the replacement
        # worker has actually started.  Retained compatible owners make the
        # start immediate, so keep ``readmission_required`` as the failure
        # tombstone until Thread.start succeeds.  Ownerless readmission uses
        # ``readmission_armed`` to carry the same authority into the next
        # compatible ordinary admission.
        source.readmission_armed = not source.active_owners
        if source.active_owners:
            error = _start_worker_locked(source)
            if error:
                # Thread.start failure is non-fatal to LCM but must not erase
                # the historical owners that explicit readmission just proved.
                source.active_owners.clear()
                source.pending_owners.clear()
                source.suspended_owners = set(compatible_owners)
                source.owner_records = retained_records
                source.owner_bindings = {
                    owner: binding for owner in compatible_owners
                }
                source.registrations = {
                    owner: record.release_handle
                    for owner, record in retained_records.items()
                }
                for owner, record in retained_records.items():
                    _set_registration_state(
                        source,
                        owner,
                        "suspended",
                        f"historical_readmission_required:{error}",
                    )
                    source.owner_records[owner] = replace(
                        record,
                        state="suspended",
                    )
                _drop_if_unowned_locked(source)
                return _registration(source_key, object(), "error", error)
        source.readmission_required = False
        source.missing_root_replacement = False
        retry = source.retry_controller
        if retry is not None:
            retry.stop()
        return _registration(source_key, object(), "active")


def periodic_backup_source_status(source_key: str) -> dict[str, Any] | None:
    with _REGISTRY_LOCK:
        source = _SCHEDULERS.get(source_key)
        if source is not None:
            _drop_if_unowned_locked(source)
            source = _SCHEDULERS.get(source_key)
        return None if source is None else source.status()


def active_periodic_backup_scheduler_count() -> int:
    with _REGISTRY_LOCK:
        return sum(1 for source in _SCHEDULERS.values() if source.thread and source.thread.is_alive())
