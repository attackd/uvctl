Overview and quickstart
=======================

uvctl lets an administrator manage ``uv tool`` installs in one shared location
(``/opt/uv`` by default) instead of per-user home directories. Everyday ``uv``
and ``uvx`` usage by regular team members is unaffected; uvctl only matters to
whoever administers the shared install.

When to use each entry point
----------------------------

- **uvctl** — install, uninstall, and manage shared tools; run ``setup``. The
  admin surface.
- **uvxg** — run a shared tool ephemerally, like ``uvx``, with no privileges
  required. For regular team members.

Quickstart
----------

.. code-block:: console

   # One-time, as root:
   $ sudo uvctl setup

   # Install a tool into the shared location (runs as the service user):
   $ uvctl tool install ruff

   # A regular user runs it (after their PATH picks up the shared bin dir):
   $ ruff --version

   # Or run it ephemerally without touching PATH:
   $ uvxg ruff --version

See :doc:`setup` for the operating modes and :doc:`cli` for the full command
reference.
