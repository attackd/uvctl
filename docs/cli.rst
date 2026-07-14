CLI reference
=============

Anything that is not a uvctl-native subcommand is forwarded verbatim to ``uv``
with the shared ``UV_TOOL_DIR`` / ``UV_TOOL_BIN_DIR`` injected.

.. code-block:: console

   $ uvctl tool install ruff
   $ uvctl tool list
   $ uvctl tool uninstall ruff

Native subcommands
------------------

- ``setup`` — see :doc:`setup`.
- ``config`` — print the effective settings, where each value came from
  (env / file / default), the detected mode and why, and whether the current
  PATH includes the shared bin dir.
- ``env`` / ``env --cron`` — emit eval-safe shell / a deterministic crontab
  ``PATH=`` line. See :doc:`automation`.
- ``run -- <tool> [args...]`` — resolve ``<tool>`` strictly from ``bin_dir`` and
  ``exec`` it. No PATH search, no ephemeral fallback.
- ``verify`` — validate the install ledger's claims against reality; exits
  non-zero on any discrepancy.
- ``link <name>`` — install an additional admin command name (a symlink) that
  behaves like ``uvctl``.

Suffixed installs
-----------------

``--suffix`` is recognized only on ``tool install`` / ``tool uninstall`` and
lets multiple versions coexist side by side. Both ``--suffix VALUE`` and
``--suffix=VALUE`` are accepted.

.. code-block:: console

   $ uvctl tool install black==24.4.2 --suffix @311
   $ uvctl tool install black==24.8.0 --suffix @312
   $ black@311 --version
   $ black@312 --version

   # Normalization makes these resolve to the same install:
   $ uvctl tool uninstall black --suffix @311

Upgrade a suffixed install in place by forwarding ``--upgrade``:

.. code-block:: console

   $ uvctl tool install black --suffix @311 --upgrade

See :doc:`limitations` for the suffix-awareness boundaries.
