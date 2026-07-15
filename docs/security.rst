Security
========

This page consolidates every security consideration in uvctl's design, so an
adopter or assessor can evaluate the tool from one document. Each item states
the rationale, the mitigation, and any residual risk.

1. Trust model and the core invariant
--------------------------------------

Package installation is arbitrary code execution (build backends, sdist hooks,
the tool at first run). **After ``uvctl setup``, no uvctl code path executes as
uid 0 in the default configuration.** Installs run as a dedicated service user
that owns only the shared tool tree and bin dir. Residual risk: granting sudo
access to uvctl in root mode (``--as-root``) is equivalent to granting root.

.. admonition:: Scope boundary — direct execution is not constrained
   :class: warning

   The invariant governs **uvctl-mediated** code paths: *installation* (run as
   the service user) and *uvctl-mediated execution* (``uvctl run`` and ``uvxg``,
   which drop before ``exec``). It says nothing about a privileged operator
   **directly executing an installed tool**.

   An installed tool is a world-executable symlink into a world-readable tree —
   it must be, so regular users can run it. Nothing stops ``sudo
   /opt/uv/bin/<tool>``, a root cron job, or root with the shared dir on its
   PATH from running that tool's code as root, entirely outside uvctl. This
   cannot be prevented: root can execute any file it can read, and a
   refuse-as-root wrapper would be trivially bypassed by running the underlying
   venv entry point directly. **Running an installed tool as root is the
   operator's decision, identical to running any other program as root.**

   What uvctl does do is keep this *non-default*: the shared bin dir is appended
   to PATH, never prepended, and setup never modifies sudo's ``secure_path``, so
   root does not get shared tools on its PATH by default (see item 8). The
   accidental case is mitigated; the deliberate one is policy. **Recommendation:
   do not add the shared bin dir to root's PATH, and run scheduled/automated
   tools as a dedicated unprivileged user, never root.**

2. Service-user isolation (rootless mode)
-----------------------------------------

In rootless mode uvctl performs a single **irrevocable whole-process drop** to
the service user at startup: after reading the root-owned config (a trusted
read, the one action done at uid 0), it calls ``initgroups`` → ``setgid`` →
``setresuid(uid, uid, uid)`` — setting the *saved* uid to the service user too,
so root can never be regained — verifies the drop by asserting ``setuid(0)``
fails, and sets ``PR_SET_DUMPABLE=0``. The call order (groups, then gid, then
uid) is load-bearing: after the uid drop the process can no longer change the
others, and inherited supplementary groups would otherwise leak privilege. All
subsequent snapshot/validation/install/symlink/ledger work then runs as direct
service-user operations. The blast radius of a malicious package is the shared
tool tree, not the system. Residual risk: a compromised service account can
still tamper with the shared tools it owns.

3. System-bin mode's narrow root surface
----------------------------------------

In system-bin mode only the final ``ln -s`` / ``rm`` into ``bin_dir`` and the
ledger write escalate to root, on already-validated paths. Because root creates
symlinks whose names originate in package metadata, name validation and
integrity checking are **mandatory** here and cannot be disabled (``--no-verify``
is a hard error). uvctl cannot obtain root on its own in this mode (the
``(uvctl)`` sudoers grant only reaches the service user), so a non-root
invocation is **refused at the front door** — before any snapshot or install
work — rather than failing mid-operation. A tripwire also asserts ``euid == 0``
immediately before any system-bin ledger write, guarding against a refactor that
reorders the privilege sequence.

4. ``--as-root`` honesty
------------------------

With ``--as-root`` package code runs as uid 0, which can rewrite snapshots, the
ledger, and uvctl itself. Integrity checking is therefore best-effort only and
**not** a security boundary against a competent attacker who already ran as
root. It still catches sloppy malware and honest mistakes.

5. uv binary resolution
-----------------------

``uv`` is never invoked by bare name in an escalated or cross-user context.
``setup`` records an absolute ``uv_path``; before each escalated call uvctl
verifies it exists and is not writable by non-root, else refuses. There is no
PATH fallback under sudo (whose result depends on ``secure_path``). Residual
risk: a root-writable ``uv`` compromised out of band.

6. Environment override risk
----------------------------

``UVCTL_TOOL_DIR`` / ``UVCTL_TOOL_BIN_DIR`` overrides can redirect writes. Two
mitigations: the escalated subprocess environment is constructed explicitly
(never the caller's, wholesale), and any active override is printed by
``config`` and every install/uninstall.

7. Name and suffix validation
-----------------------------

Executable names discovered in the scratch bin dir come from package metadata
and are attacker-controlled. They must be bare basenames over a conservative
charset (``[A-Za-z0-9._+@-]``), no leading ``-``, no whitespace/NUL; the suffix
follows the same rules with a length bound and a ``..`` reject. This defends
against directory traversal, argv confusion, and clobbering. Validation happens
before any privileged operation consumes the value.

8. Collision and shadowing policy
---------------------------------

The shared bin dir is always appended (never prepended) to PATH, so shared
tools cannot shadow system binaries. Symlink creation never uses blind
``ln -sf``: a foreign collision is refused without ``--force``. An install-time
warning fires when a new name shadows something already on the system PATH.
Root's ``secure_path`` typically excludes the shared dir, and setup never
offers to modify it.

9. Deletion guards
------------------

Before any recursive delete, the target is resolved with ``realpath`` and must
be a real directory strictly inside ``<tool_dir>/.suffixed/`` and not itself a
symlink. Uninstall removes only ``bin_dir`` symlinks whose targets resolve
inside the matching scratch dir (target-based matching, never by name). The
recursive delete runs **as the service user** (the scratch tree's owner), never
as root — so even in system-bin mode a check-to-use race cannot redirect a
privileged ``rm`` outside the tree; the worst an attacker who wins the race
achieves is deleting something the service user could already delete.

10. Integrity checking
----------------------

Per-run snapshots (no persistent baseline — that would turn routine out-of-band
changes into false positives and train the disable reflex). Findings are
reported as "changes not attributable to this install".

**Scope is ``bin_dir`` only.** In rootless mode package hooks run as the
unprivileged service user and cannot write to a root-owned system dir, so
monitoring ``/usr/local/bin`` there could only ever flag concurrent unrelated
activity and spuriously abort a legitimate install; in system-bin mode
``bin_dir`` *is* ``/usr/local/bin``, so the root-adjacent dir stays monitored
where the risk lives. Every finding is thus attributable to something the
monitored principal could actually have done.

**Suffixed installs** use a three-point snapshot (pre / post-uv / final); uv
writes only to the out-of-scope scratch tree, so any in-scope change is a
finding and **fails closed** — links nothing, no ledger entry, scratch cleaned
up. **Plain installs** use a two-point snapshot with **target-based
attribution**: a created/retargeted symlink is expected only when it is a
*canonical* uv entrypoint — resolving to exactly ``<tool_env>/bin/<same
basename>`` (or a deletion of one that did — upgrades clearing stale
entrypoints). This name-matched form is deliberate: attributing *any* symlink
that merely resolves somewhere inside the env would let a build hook plant an
arbitrarily-named entrypoint (``bin/kubectl`` -> ``env/bin/evil``) and have it
pass as expected. Anything else is a finding. uv has
already linked by then, so the fail-closed analog is: report, best-effort
rollback (``uv tool uninstall``), non-zero exit. **Plain uninstalls** apply the
same classifier (expected = deletions resolving into the tool's env); on
findings, report and exit non-zero.

**Never-delete boundary (all modes, all paths):** uvctl never auto-deletes the
unattributed files it finds — a detection tool that deletes unknown files
becomes the incident. It removes only its own work product (suffix scratch, or
rollback of the tool uv just installed) and leaves the unknown files for the
admin.

**Mechanism assumption:** target-based attribution assumes uv installs
entrypoints as symlinks into the tool environment. A tier-2 test asserts this;
if a future uv switches to copied entrypoints, the defined fallback is
attribution by name against the tool env's ``bin/`` contents. The test failing
is the activation signal, never a silent behavior change.

``--no-verify`` (rootless only) skips the snapshot machinery entirely rather
than half-running it, and always records a ``verify_skipped`` audit event; in
system-bin mode it is a hard error.

11. In-memory snapshot protection
---------------------------------

The pre-snapshot is protected by OS process and user isolation (package code
runs in a subprocess, as a different user), not by Python immutability, which
does not truly exist. The frozen dataclasses and ``MappingProxyType`` catch
uvctl's own bugs; a serialize-and-hash tripwire aborts the run if uvctl mutates
the snapshot before diffing.

12. Ledger and audit log
------------------------

``/var/lib/uvctl/`` holds a record of what uvctl *did* — never a baseline of
what a directory should contain, and never consulted to decide whether the
environment is "clean". ``SUDO_USER`` attribution names the operator behind a
sudo invocation for incident response.

In rootless mode the ledger is service-user-owned (the whole-process drop means
uvctl writes it as the service user), so the same principal whose installs it
records can also rewrite it. Every audit event is therefore mirrored to
**syslog** (``LOG_AUTHPRIV``, one ``key=value`` line per event). This on-host
mirror is tamper-*evident* beyond the service user's reach — **not**
tamper-proof: a compromised service account cannot quietly alter it, but only
forwarding to a remote collector makes the trail truly durable (deployment
guidance, not something uvctl can do for you). If ``/dev/log`` is absent the
mirror degrades with a single warning and the ledger remains the primary
record.

13. Permissions and umask
-------------------------

Escalated subprocesses force umask 022 regardless of the caller's umask, so a
hardened host (umask 077) still yields a world-readable tree. Pinning
``UV_PYTHON_INSTALL_DIR`` to the shared location is load-bearing: a managed
Python under the caller's home would symlink an interpreter regular users
cannot traverse, breaking every tool at runtime.

14. sudoers fragment
--------------------

``setup --write-sudoers`` is opt-in only (many teams manage sudoers via
configuration management). The fragment is validated with ``visudo -cf`` before
installation; on failure uvctl aborts without installing. A malformed sudoers
fragment can lock out sudo entirely.

15. Empty-PATH shell hazard
---------------------------

Emitted PATH snippets use ``${PATH:+${PATH}:}`` so an empty or unset PATH yields
the shared dir alone, never a leading empty element — which POSIX shells
interpret as the current directory, a security regression.

16. Dependency policy
---------------------

The runtime is standard-library only. The sole permitted dependency is the
pure-Python ``tomli`` backport, and only on Python < 3.11. This minimizes
supply-chain surface adjacent to privilege transitions and avoids
version-conflict hazards in system site-packages. ``packaging`` is explicitly
disallowed; requirement-name parsing is hand-rolled with ``re``. CI asserts the
built distribution declares nothing beyond the conditional ``tomli`` and that no
runtime module imports a third-party package.

17. Comparison: pipx ``--global``
---------------------------------

pipx 1.5+ offers ``sudo pipx install --global``, installing to
``PIPX_GLOBAL_HOME`` (default ``/opt/pipx``) with executables in
``/usr/local/bin``. It is the closest existing tool to uvctl. Two differences
define uvctl:

1. pipx ``--global`` executes package build hooks and install-time code as
   uid 0; uvctl never executes package code as root after setup (the core
   invariant — rootless mode runs it as an unprivileged service user, and even
   system-bin mode confines root to symlink and ledger writes).
2. pipx performs no integrity checking; uvctl snapshots ``bin_dir`` around every
   forwarded install/uninstall and attributes every change, with findings
   aborting (suffixed) or rolling back (plain).

uvctl's system-bin mode is approximately pipx-global parity in outcome (tools in
``/usr/local/bin``) with the root surface reduced and monitored. This is an
architecture statement, not marketing: it cuts both ways — pipx's design
vindicates the rootless privilege model as uvctl's differentiator, and pipx
doing no monitoring supports trimming ours to only what the monitored principal
could have done.
