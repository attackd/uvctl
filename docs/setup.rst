Setup and operating modes
=========================

``uvctl setup``
---------------

``setup`` is the only phase that legitimately requires root. It is idempotent
(safe to re-run) and:

#. creates the service user (a system account, no login shell);
#. creates ``tool_dir`` / ``bin_dir`` / ``python_install_dir`` / ``cache_dir``,
   owned by the service user, mode 755;
#. records the absolute ``uv`` path in the config;
#. writes ``/etc/uvctl/config.toml`` (root-owned, 644);
#. creates ``/var/lib/uvctl/`` for the ledger and audit log;
#. writes the guarded ``/etc/profile.d/uvctl.sh`` snippet;
#. optionally, with ``--write-sudoers``, installs a ``visudo``-validated
   sudoers fragment.

.. code-block:: console

   $ sudo uvctl setup --service-user uvctl
   $ sudo uvctl setup --repair          # re-apply ownership/modes

Operating modes
---------------

The mode is *detected* from who owns ``bin_dir``, not configured directly.

Rootless mode (default)
~~~~~~~~~~~~~~~~~~~~~~~~~

``bin_dir`` defaults to ``/opt/uv/bin``, owned by the service user. Installs,
symlink creation, and uninstalls all run as the service user. No uvctl code
path holds root after setup. Integrity checking is on by default, with a
``--no-verify`` escape hatch.

System-bin mode (opt-in)
~~~~~~~~~~~~~~~~~~~~~~~~~~

For teams that configure ``bin_dir = /usr/local/bin`` (or another root-owned
directory). The ``uv`` install still runs as the service user; only the final
symlink create/remove into ``bin_dir`` and the ledger write escalate to root.
Integrity checking and name validation are **mandatory** and cannot be disabled
in this mode.

Root usage policy
-----------------

- A habitual ``sudo uvctl tool install ...`` transparently drops to the service
  user for the install.
- A true root-owned install requires ``--as-root`` or ``UVCTL_ALLOW_ROOT=1``
  and prints a warning that package code will execute as uid 0 and that
  integrity checking is then best-effort only.

Granting sudo access to uvctl in root mode is equivalent to granting root.
