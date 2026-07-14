# uvctl

Manage shared `uv tool` installs for a team or shared server in one location,
without ever running package code as root.

Two console entry points:

- **`uvctl`** — the admin/control surface. Forwards to `uv` (primarily
  `uv tool ...`) against a shared `UV_TOOL_DIR` / `UV_TOOL_BIN_DIR`, running
  installs as a dedicated non-root service user. Use it to install/manage.
- **`uvxg`** — a read-only companion to `uvx` that checks the shared install
  first. Never escalates privileges. For regular team members.

### Core security invariant

> After `uvctl setup` completes, no uvctl code path executes as uid 0 in the
> default configuration.

Package installation runs arbitrary code, so uvctl runs it as a dedicated
service user, never root. Only `setup` needs root. See the
[security documentation](./docs/security.rst) for the full trust model.

**Scope boundary:** the invariant covers uvctl-mediated paths — installation and
`uvctl run` / `uvxg` (which drop before exec). It does **not** stop a privileged
operator from *directly* running an installed tool as root (`sudo
/opt/uv/bin/<tool>`, a root cron job, etc.) — root can execute any file it can
read, and that is unpreventable by design. uvctl keeps it non-default (the
shared dir is never on root's PATH by default; setup never touches
`secure_path`). Don't add the shared bin dir to root's PATH, and run automated
tools as a dedicated unprivileged user, not root.

## Quickstart

```sh
sudo uvctl setup                 # one-time, as root
uvctl tool install ruff          # installs as the service user
ruff --version                   # a regular user runs it
uvxg ruff --version              # or run it ephemerally, no privileges
```

## Operating modes

Mode is *detected* from who owns `bin_dir`:

- **Rootless** (default, `bin_dir=/opt/uv/bin`): everything runs as the service
  user; no root after setup. Integrity checking on by default (`--no-verify`
  escape hatch).
- **System-bin** (opt-in, `bin_dir=/usr/local/bin`): only the final
  `ln -s`/`rm` into `bin_dir` and the ledger write escalate to root. Integrity
  checking and name validation are **mandatory** here.

A habitual `sudo uvctl ...` transparently drops to the service user. A true
root-owned install requires `--as-root` (or `UVCTL_ALLOW_ROOT=1`) and prints a
warning that integrity checking is then best-effort only.

## Side-by-side versions with `--suffix`

`--suffix` (on `tool install` / `tool uninstall` only) keeps multiple versions
of a tool side by side:

```sh
uvctl tool install black==24.4.2 --suffix @311
uvctl tool install black==24.8.0 --suffix @312
black@311 --version
black@312 --version

# Normalization resolves these to the same install:
uvctl tool uninstall black --suffix @311

# Upgrade a suffixed install in place:
uvctl tool install black --suffix @311 --upgrade
```

Known limitations: `tool list` / `tool upgrade` are not suffix-aware; `uvxg`
cannot see suffixed installs (use `uvctl run -- black@311`).

## Other commands

- `uvctl config` — effective settings, their source, the detected mode, and
  whether your PATH includes the shared bin dir.
- `uvctl env` / `uvctl env --cron` — eval-safe shell / a deterministic crontab
  `PATH=` line.
- `uvctl run -- <tool>` — resolve strictly from `bin_dir` and exec; no PATH
  search, no ephemeral fallback (for automation).
- `uvctl verify` — validate the install ledger against reality.
- `uvctl link <name>` — an additional admin command name.

## Automation

```
# crontab
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/uv/bin
0 3 * * *  uvctl run -- semgrep --config auto /srv/app
```

```ini
# systemd unit
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/uv/bin
```

`uvxg` for humans at interactive shells; `uvctl run` for automation that needs
deterministic behavior. profile.d covers interactive login shells only.

## Why not `pipx --global`?

pipx 1.5+ has `sudo pipx install --global` (tools in `/usr/local/bin`), the
closest existing tool. Two differences define uvctl: pipx runs package build
hooks and install code **as root**, which uvctl never does after setup (the core
invariant); and pipx does **no integrity checking**, whereas uvctl snapshots
`bin_dir` around every install/uninstall and attributes every change (findings
abort or roll back, and unattributed files are reported, never auto-deleted).
uvctl's system-bin mode reaches pipx-global's outcome with the root surface
reduced and monitored.

## Uninstalling uvctl

Uninstalling the uvctl package follows system-package convention: it leaves the
service user, data directories, config, and ledger in place.

## Developing

```sh
make test        # tier 1: host-safe unit tests (uv venv, no root)
make test-system # tier 2: system tests inside a disposable container
make lint        # ruff, including docstring (D) rules
make docs        # build the Sphinx docs
```

Tests are split into two tiers: host-safe unit tests (`make test`) and
system-level tests that mutate users/dirs/sudoers and therefore run **only**
inside the disposable container (`make test-system`) — never on your host. See
the [security documentation](./docs/security.rst) for the trust model.
