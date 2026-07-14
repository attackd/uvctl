"""Per-run, three-point integrity snapshots.

Trust role: reads only; holds no privilege. Records ``bin_dir`` (and only
``bin_dir``) before the uv subprocess, after it, and after uvctl's own linking,
to separate package-attributed changes (pre vs post) from uvctl-attributed ones
(post vs final). The scope is deliberately *just* ``bin_dir``: in rootless mode
package hooks run as the service user and cannot write to a root-owned system
dir, so monitoring ``/usr/local/bin`` there could only ever flag concurrent
unrelated activity and spuriously abort a legitimate install; in system-bin mode
``bin_dir`` *is* ``/usr/local/bin``, so the root-adjacent dir stays monitored
where the risk actually lives. There is **no persistent baseline**: a
persistent baseline turns every legitimate out-of-band change into a false
positive, and a check that alarms on routine activity gets disabled within a
month. This module answers "did anything change in this seconds-long window",
not "has this directory been pristine since setup".

In-memory protection: the untrusted package code runs in a **subprocess** as a
**different user**, so it never shares an address space with uvctl and cannot
reach these objects. The frozen dataclasses and :class:`~types.MappingProxyType`
here are not a security boundary (both are bypassable from inside the same
interpreter); they exist to catch *uvctl's own bugs*. The
serialize-and-hash tripwire (:func:`fingerprint` / :func:`verify_fingerprint`)
is the self-bug detector: if uvctl's code mutates the pre-snapshot before
diffing, the run aborts loudly.

Report language is deliberately "changes not attributable to this install",
never "tampering": the window is short but an unrelated concurrent change (a
second admin, a package-manager run) can legitimately land inside it.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

# Entry fields compared when deciding whether an entry was modified. ``name`` is
# excluded because it is already encoded in the entry's path key.
_COMPARED_FIELDS = ("kind", "target", "size", "mode", "uid", "gid", "sha256")

_READ_CHUNK = 1 << 16


class SnapshotMutationError(RuntimeError):
    """Raised when a snapshot's fingerprint changes between capture and diff.

    A mismatch means uvctl's own code mutated a snapshot that is supposed to be
    write-once. This is a self-bug detector, not an attack signal; the run
    aborts rather than diffing against corrupted state.
    """


@dataclass(frozen=True)
class Entry:
    """Immutable record of one directory entry at snapshot time.

    Attributes:
        name: The entry's basename.
        kind: One of ``"file"``, ``"symlink"``, ``"dir"``, ``"other"``.
        target: The symlink target for a symlink, else None.
        size: ``lstat`` size in bytes (the link's own size for a symlink).
        mode: The full ``st_mode`` (type + permission bits).
        uid: Owning user id.
        gid: Owning group id.
        sha256: Hex content digest for a regular file, else None.
    """

    name: str
    kind: str
    target: str | None
    size: int
    mode: int
    uid: int
    gid: int
    sha256: str | None


@dataclass(frozen=True)
class Snapshot:
    """An immutable, read-once view of one or more scoped directories.

    Attributes:
        roots: The directories scanned, in the order requested.
        entries: A read-only mapping from absolute path to :class:`Entry`,
            covering the immediate (non-recursive) children of each existing
            root.
    """

    roots: tuple[str, ...]
    entries: Mapping[str, Entry]

    @classmethod
    def capture(cls, roots: tuple[str, ...] | list[str]) -> Snapshot:
        """Scan ``roots`` and return an immutable snapshot of their contents.

        Nonexistent roots contribute no entries (they are still kept in
        ``roots`` for the record). The scan is non-recursive: bin directories
        are flat, and their file counts are small.

        Args:
            roots: Directories to scan.

        Returns:
            A new :class:`Snapshot`.
        """
        roots = tuple(roots)
        collected: dict[str, Entry] = {}
        for root in roots:
            if not os.path.isdir(root):
                continue
            with os.scandir(root) as it:
                for entry in it:
                    collected[entry.path] = _entry_for(entry.path)
        ordered = MappingProxyType(dict(sorted(collected.items())))
        return cls(roots=roots, entries=ordered)


@dataclass(frozen=True)
class Change:
    """One difference between two snapshots.

    Attributes:
        path: The absolute path that changed.
        kind: ``"added"``, ``"removed"``, or ``"modified"``.
        before: The prior :class:`Entry` (None for an addition).
        after: The new :class:`Entry` (None for a removal).
        fields: For a modification, the entry fields that differ; empty
            otherwise.
    """

    path: str
    kind: str
    before: Entry | None
    after: Entry | None
    fields: tuple[str, ...]


def scope_for(bin_dir: str) -> tuple[str, ...]:
    """Return the snapshot scope for an install into ``bin_dir``.

    Scope is deliberately **just** ``bin_dir``. Monitoring ``/usr/local/bin`` in
    rootless mode (where package hooks run as the unprivileged service user and
    cannot write there) would only ever flag concurrent unrelated activity and,
    under abort-on-findings, spuriously kill legitimate installs. In system-bin
    mode ``bin_dir`` already *is* ``/usr/local/bin``, so the root-adjacent dir
    stays monitored where the risk lives. Every finding in scope is therefore
    attributable to something the monitored principal could actually do.

    Args:
        bin_dir: The effective shared bin directory.

    Returns:
        ``(bin_dir,)``.
    """
    return (bin_dir,)


def _entry_for(path: str) -> Entry:
    """Build an :class:`Entry` from a path using ``lstat`` (never following links)."""
    st = os.lstat(path)
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        kind, target, sha = "symlink", os.readlink(path), None
    elif stat.S_ISDIR(mode):
        kind, target, sha = "dir", None, None
    elif stat.S_ISREG(mode):
        kind, target, sha = "file", None, _sha256(path)
    else:
        kind, target, sha = "other", None, None
    return Entry(
        name=os.path.basename(path),
        kind=kind,
        target=target,
        size=st.st_size,
        mode=mode,
        uid=st.st_uid,
        gid=st.st_gid,
        sha256=sha,
    )


def _sha256(path: str) -> str:
    """Return the hex SHA-256 of a regular file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_READ_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _canonical(snapshot: Snapshot) -> bytes:
    """Serialize a snapshot to canonical, sorted bytes for hashing."""
    payload = {
        "roots": list(snapshot.roots),
        "entries": {
            path: [e.name, e.kind, e.target, e.size, e.mode, e.uid, e.gid, e.sha256]
            for path, e in sorted(snapshot.entries.items())
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fingerprint(snapshot: Snapshot) -> str:
    """Return a canonical SHA-256 fingerprint of a snapshot.

    Taken immediately after the pre-snapshot and re-checked before diffing, so
    an in-process mutation of the write-once snapshot is detected. Costs
    microseconds.

    Args:
        snapshot: The snapshot to fingerprint.

    Returns:
        A hex digest that is identical for two snapshots with identical
        contents.
    """
    return hashlib.sha256(_canonical(snapshot)).hexdigest()


def verify_fingerprint(snapshot: Snapshot, expected: str) -> str:
    """Assert a snapshot still matches a previously recorded fingerprint.

    Args:
        snapshot: The snapshot to re-check.
        expected: The fingerprint captured right after the snapshot was taken.

    Returns:
        The freshly computed fingerprint (equal to ``expected``).

    Raises:
        SnapshotMutationError: If the snapshot no longer matches ``expected``,
            meaning uvctl's own code mutated write-once state.
    """
    actual = fingerprint(snapshot)
    if actual != expected:
        raise SnapshotMutationError(
            "snapshot fingerprint changed between capture and diff; "
            "uvctl mutated write-once state — aborting"
        )
    return actual


def diff(before: Snapshot, after: Snapshot) -> tuple[Change, ...]:
    """Compute the changes from ``before`` to ``after``.

    Args:
        before: The earlier snapshot.
        after: The later snapshot.

    Returns:
        Additions, removals, and modifications, ordered by path within each
        category (added, then removed, then modified).
    """
    b, a = before.entries, after.entries
    bkeys, akeys = set(b), set(a)
    changes: list[Change] = []
    for path in sorted(akeys - bkeys):
        changes.append(Change(path, "added", None, a[path], ()))
    for path in sorted(bkeys - akeys):
        changes.append(Change(path, "removed", b[path], None, ()))
    for path in sorted(akeys & bkeys):
        be, ae = b[path], a[path]
        differing = tuple(
            f for f in _COMPARED_FIELDS if getattr(be, f) != getattr(ae, f)
        )
        if differing:
            changes.append(Change(path, "modified", be, ae, differing))
    return tuple(changes)


def unattributed(
    changes: tuple[Change, ...],
    *,
    allowed_added: tuple[str, ...] | list[str] = (),
) -> tuple[Change, ...]:
    """Filter out the changes a caller expected, leaving the unexplained ones.

    The caller knows exactly which paths it intended to add (its link set), so
    it passes them as ``allowed_added``; every other change — including an
    unexpected removal or modification of an allowed path — survives as a
    finding.

    Args:
        changes: The result of :func:`diff`.
        allowed_added: Paths the caller intentionally created (e.g. the exact
            symlinks uvctl linked between the post and final snapshots).

    Returns:
        The changes not attributable to the caller's intended action.
    """
    allowed = set(allowed_added)
    return tuple(c for c in changes if not (c.kind == "added" and c.path in allowed))


def format_report(changes: tuple[Change, ...]) -> str:
    """Render changes as a human report using the required, careful language.

    Args:
        changes: Typically the output of :func:`unattributed`.

    Returns:
        A multi-line string. When there are no changes, a single line stating
        so; otherwise a header ("Changes not attributable to this install")
        and one line per change. Never uses the word "tampering".
    """
    if not changes:
        return "No changes not attributable to this install."
    lines = ["Changes not attributable to this install:"]
    for c in changes:
        if c.kind == "added":
            lines.append(f"  + {c.path} ({c.after.kind})")
        elif c.kind == "removed":
            lines.append(f"  - {c.path} ({c.before.kind})")
        else:
            lines.append(f"  ~ {c.path} (changed: {', '.join(c.fields)})")
    return "\n".join(lines)
