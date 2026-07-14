uvctl
=====

Manage shared ``uv tool`` installs for a team or shared server in one location,
without ever running package code as root.

.. admonition:: Core security invariant

   After ``uvctl setup`` completes, no uvctl code path executes as uid 0 in the
   default configuration.

uvctl ships two console entry points:

- **uvctl** — the admin/control surface. Forwards to ``uv`` (primarily
  ``uv tool ...``) against a shared ``UV_TOOL_DIR`` / ``UV_TOOL_BIN_DIR``,
  running installs as a dedicated non-root service user.
- **uvxg** — a read-only companion to ``uvx`` that checks the shared install
  first. Never escalates privileges.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   overview
   setup
   cli
   automation
   security
   limitations
   api
