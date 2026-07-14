Known limitations
=================

- **Suffix-awareness is limited to install/uninstall.** ``tool list`` and
  ``tool upgrade`` are not suffix-aware in this build; upgrade a suffixed
  install with ``uvctl tool install <pkg> --suffix <sfx> --upgrade``.
- **uvxg cannot see suffixed installs.** They live in a ``.suffixed/`` scratch
  tree, so ``uvxg black@311`` will fail or attempt to resolve a PyPI package
  literally named ``black@311``. Use ``uvctl run -- black@311`` or execute the
  ``bin_dir`` symlink directly.
- **profile.d covers interactive login shells only.** See :doc:`automation` for
  cron, systemd, and non-login contexts.
- **install-all is deferred.** The install ledger is designed so a future
  ``install-all`` can be built on top of it without an on-disk layout change,
  but it is not part of this build.
