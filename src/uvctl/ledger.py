"""Install ledger and audit log.

Trust role: writes a root-owned record under ``/var/lib/uvctl/`` of what uvctl
*did* — never a baseline of what a directory should contain, and never consulted
to decide whether the environment is "clean". It cannot go stale the way a
directory baseline does, because it only ever claims "here is what uvctl did".

The install ledger records, per install, the normalized package name, requested
spec, suffix, timestamp, invoking user (``SUDO_USER`` when present, else the
real uid's name), operating mode, scratch location, the exact executables
linked with their targets, and a completion state; uninstall marks entries
removed. The audit log is append-only: one line per escalated/cross-user
operation. Both are plain data writes, never code execution.

This module performs the *file* operations only; whether that write is done as
root or as the service user is decided by :mod:`uvctl.escalate`. Functions take
explicit paths and an injectable clock so they are fully unit-testable without
touching ``/var/lib``.
"""

from __future__ import annotations

import json
import os
import pwd
import sys
import syslog
import time
from collections.abc import Callable, Sequence

#: Root-owned state directory (mode 755), created by ``setup``.
LEDGER_DIR = "/var/lib/uvctl"
#: Install ledger file (mode 644).
LEDGER_PATH = f"{LEDGER_DIR}/ledger.json"
#: Append-only audit log (mode 644).
AUDIT_PATH = f"{LEDGER_DIR}/audit.log"

#: On-disk schema version, so a future ``install-all`` can migrate safely.
LEDGER_VERSION = 1

_FILE_MODE = 0o644

# Completion states recorded per install (see the partial-failure policy).
STATE_COMPLETE = "complete"
STATE_PARTIAL = "partial"


def invoking_user(environ: dict[str, str] | None = None) -> str:
    """Return the human to attribute an action to.

    Prefers ``SUDO_USER`` (the operator behind a ``sudo`` invocation) over the
    effective account, so the audit trail names a person rather than the
    service user.

    Args:
        environ: Environment mapping; defaults to :data:`os.environ`.

    Returns:
        The attributed username.
    """
    env = os.environ if environ is None else environ
    sudo_user = env.get("SUDO_USER")
    if sudo_user:
        return sudo_user
    return pwd.getpwuid(os.getuid()).pw_name


def build_install_record(
    *,
    package: str,
    spec: str,
    suffix: str | None,
    mode: str,
    executables: Sequence[dict[str, str]],
    scratch_dir: str | None = None,
    user: str,
    timestamp: float,
    state: str = STATE_COMPLETE,
) -> dict[str, object]:
    """Assemble one install ledger record.

    Args:
        package: PEP 503-normalized project name (the ledger key with
            ``suffix``).
        spec: The raw requirement spec as requested (e.g. ``black==24.4.2``).
        suffix: The suffix for a suffixed install, else None.
        mode: The operating mode in effect (``rootless`` / ``system-bin``).
        executables: One ``{"name", "link", "target"}`` mapping per linked
            executable.
        scratch_dir: The scratch location for a suffixed install, else None.
        user: Attributed user (see :func:`invoking_user`).
        timestamp: Unix time of the install.
        state: Completion state (:data:`STATE_COMPLETE` or
            :data:`STATE_PARTIAL`).

    Returns:
        A JSON-serializable record.
    """
    return {
        "package": package,
        "spec": spec,
        "suffix": suffix,
        "mode": mode,
        "scratch_dir": scratch_dir,
        "executables": [dict(e) for e in executables],
        "user": user,
        "timestamp": timestamp,
        "state": state,
        "removed": False,
    }


def empty_ledger() -> dict[str, object]:
    """Return a fresh, empty ledger structure."""
    return {"version": LEDGER_VERSION, "installs": []}


def load_ledger(path: str = LEDGER_PATH) -> dict[str, object]:
    """Load the ledger, returning an empty structure when the file is absent.

    Args:
        path: Ledger file path.

    Returns:
        The parsed ledger, or :func:`empty_ledger` when missing.

    Raises:
        json.JSONDecodeError: If the file exists but is not valid JSON.
    """
    if not os.path.exists(path):
        return empty_ledger()
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_ledger(data: dict[str, object], path: str = LEDGER_PATH) -> None:
    """Write the ledger atomically with mode 644.

    Writes to a temporary sibling and renames, so a crash mid-write cannot
    corrupt the ledger.

    Args:
        data: The ledger structure to persist.
        path: Ledger file path.
    """
    _atomic_write_json(path, data)


def _atomic_write_json(path: str, data: object) -> None:
    """Serialize ``data`` to ``path`` atomically, mode 644."""
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, _FILE_MODE)  # defeat the caller's umask on the final mode
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _matches(record: dict[str, object], package: str, suffix: str | None) -> bool:
    """Whether a record is keyed by ``(package, suffix)`` and still active."""
    return (
        record.get("package") == package
        and record.get("suffix") == suffix
        and not record.get("removed", False)
    )


def record_install(
    record: dict[str, object],
    path: str = LEDGER_PATH,
) -> dict[str, object]:
    """Append (or replace an active entry with) an install record and persist.

    A re-install of the same ``(package, suffix)`` replaces the prior active
    record rather than duplicating it (mirroring idempotent re-runs).

    Args:
        record: A record from :func:`build_install_record`.
        path: Ledger file path.

    Returns:
        The updated ledger.
    """
    ledger = load_ledger(path)
    installs = [
        r
        for r in ledger["installs"]  # type: ignore[index]
        if not _matches(r, record["package"], record["suffix"])  # type: ignore[arg-type]
    ]
    installs.append(record)
    ledger["installs"] = installs
    save_ledger(ledger, path)
    return ledger


def mark_removed(
    package: str,
    suffix: str | None,
    path: str = LEDGER_PATH,
) -> bool:
    """Mark the active install record for ``(package, suffix)`` as removed.

    Args:
        package: Normalized package name.
        suffix: Suffix, or None for an unsuffixed install.
        path: Ledger file path.

    Returns:
        True if a matching active record was found and marked; False otherwise.
    """
    ledger = load_ledger(path)
    found = False
    for record in ledger["installs"]:  # type: ignore[union-attr]
        if _matches(record, package, suffix):
            record["removed"] = True
            found = True
    if found:
        save_ledger(ledger, path)
    return found


def find_active(
    package: str,
    suffix: str | None,
    path: str = LEDGER_PATH,
) -> dict[str, object] | None:
    """Return the active install record for ``(package, suffix)``, if any.

    Args:
        package: Normalized package name.
        suffix: Suffix, or None for an unsuffixed install.
        path: Ledger file path.

    Returns:
        The matching record, or None.
    """
    ledger = load_ledger(path)
    for record in ledger["installs"]:  # type: ignore[union-attr]
        if _matches(record, package, suffix):
            return record
    return None


def build_audit_entry(
    *,
    user: str,
    mode: str,
    command: Sequence[str],
    outcome: str,
    timestamp: float,
) -> dict[str, object]:
    """Assemble one audit-log entry.

    Args:
        user: Attributed user (see :func:`invoking_user`).
        mode: Operating mode in effect.
        command: The exact forwarded command vector.
        outcome: Short outcome string (e.g. ``ok``, ``failed``, an exit code).
        timestamp: Unix time of the operation.

    Returns:
        A JSON-serializable entry.
    """
    return {
        "timestamp": timestamp,
        "user": user,
        "mode": mode,
        "command": list(command),
        "outcome": outcome,
    }


def append_audit(entry: dict[str, object], path: str = AUDIT_PATH) -> None:
    """Append one JSON line to the audit log (created mode 644 if absent).

    Args:
        entry: An entry from :func:`build_audit_entry`.
        path: Audit log path.
    """
    line = json.dumps(entry, sort_keys=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _FILE_MODE)
    os.fchmod(fd, _FILE_MODE)  # defeat the caller's umask on first creation
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line)


# --- syslog mirror -----------------------------------------------------------

_syslog_warned = False
_syslog_opened = False


def format_audit_kv(fields: dict[str, object]) -> str:
    """Render audit fields as a single ``key=value`` line (insertion order).

    Args:
        fields: Structured audit fields (space-free values).

    Returns:
        A one-line ``key=value key=value ...`` string.
    """
    return " ".join(f"{key}={value}" for key, value in fields.items())


def mirror_to_syslog(fields: dict[str, object]) -> None:
    """Mirror one audit event to syslog (best effort, tamper-evident trail).

    Uses the stdlib ``syslog`` module (ident ``uvctl``, facility
    ``LOG_AUTHPRIV``). When ``/dev/log`` is absent (e.g. minimal containers),
    warns once and continues — the ledger remains the primary record.

    Args:
        fields: Structured audit fields; rendered by :func:`format_audit_kv`.
    """
    global _syslog_warned, _syslog_opened
    if not os.path.exists("/dev/log"):
        if not _syslog_warned:
            print(
                "uvctl: /dev/log absent; audit syslog mirror disabled "
                "(ledger remains the primary record)",
                file=sys.stderr,
            )
            _syslog_warned = True
        return
    try:
        if not _syslog_opened:
            syslog.openlog(ident="uvctl", facility=syslog.LOG_AUTHPRIV)
            _syslog_opened = True
        syslog.syslog(syslog.LOG_INFO, format_audit_kv(fields))
    except OSError:  # never let audit mirroring break an operation
        pass


def emit_audit(
    event: str,
    *,
    timestamp: float,
    user: str,
    mode: str,
    path: str = AUDIT_PATH,
    **fields: object,
) -> dict[str, object]:
    """Record one structured audit event to the log **and** mirror it to syslog.

    Args:
        event: Event type (``install``, ``uninstall``, ``verify_skipped``,
            ``refused``, ...).
        timestamp: Unix time of the event.
        user: Attributed user (see :func:`invoking_user`).
        mode: Operating mode in effect.
        path: Audit log path.
        **fields: Additional structured fields (e.g. ``pkg``, ``suffix``,
            ``outcome``). Values should be space-free for the syslog line.

    Returns:
        The recorded entry.
    """
    entry = {
        "timestamp": timestamp,
        "event": event,
        "user": user,
        "mode": mode,
        **fields,
    }
    # The syslog mirror is the tamper-evident trail and any uid can write it; the
    # local audit file may be unwritable (e.g. a non-root refusal in system-bin),
    # so a file-write failure must not suppress the mirror or crash the caller.
    try:
        append_audit(entry, path)
    except OSError:
        pass
    mirror_to_syslog({"event": event, "user": user, "mode": mode, **fields})
    return entry


def now(clock: Callable[[], float] = time.time) -> float:
    """Return the current Unix time (injectable for deterministic tests).

    Args:
        clock: A callable returning Unix time; defaults to :func:`time.time`.

    Returns:
        The current time as a float.
    """
    return clock()
