Automation guide
=================

profile.d covers interactive login shells and little else. Cron, systemd units,
and non-login shells will not see ``/opt/uv/bin`` unless you add it. uvctl
offers three supported answers.

``uvctl env``
-------------

For anything that can ``eval`` shell (login-adjacent contexts, deploy scripts):

.. code-block:: console

   $ eval "$(uvctl env)"

It emits a guarded, empty-safe, trailing-append PATH line (omitted entirely if
the shared dir is already present) plus the ``UV_TOOL_DIR`` pair.

``uvctl env --cron``
--------------------

Cron variable lines are not shell and do not expand ``${PATH}``, so the line is
a full, deterministic replacement built from a fixed system-dir list plus the
shared dir last:

.. code-block:: text

   # Place at the top of the crontab, before any job lines.
   PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/uv/bin

``uvctl run`` for automation
----------------------------

For cron/systemd jobs that should not touch the environment at all:

.. code-block:: text

   0 3 * * *  uvctl run -- semgrep --config auto /srv/app

``uvctl run`` resolves strictly from ``bin_dir`` and fails loudly if the tool is
absent — never an ephemeral download.

systemd
-------

Add the shared dir to a unit's environment explicitly:

.. code-block:: ini

   [Service]
   Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/uv/bin

``uvxg`` vs ``uvctl run``
-------------------------

Use **uvxg** for humans at interactive shells (uvx semantics, ephemeral
fallback allowed); use **uvctl run** for automation that needs deterministic
behavior or a loud failure.
