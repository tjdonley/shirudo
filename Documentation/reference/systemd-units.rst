..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

systemd units and timers
========================

The units the target package installs, from ``systemd/*.in`` and
``systemd/*.timer``. Every service is ``Type=oneshot``: shirudo runs no
daemon. Every service sets ``SyslogIdentifier=shirudo``, so what it writes
to standard output and standard error reaches the journal under the same
identifier as the messages it sends to syslog, whatever the name of the
process that runs the binary. A message is in the journal once: under a
unit shirudo sends it to syslog and not to standard error as well.

Units
-----

.. list-table::
   :header-rows: 1
   :widths: 30 38 32

   * - Unit
     - Runs
     - Started by
   * - ``shirudo-initrd.service``
     - ``@bindir@/shirudo init`` in the initrd
     - ``initrd.target``, once per boot
   * - ``shirudo.service``
     - ``@bindir@/shirudo init $SHIRUDO_INIT_ARGS``, replaced by the
       runtime drop-in
     - ``sysinit.target``, once per boot
   * - ``shirudo-keepalive.service``
     - ``@bindir@/shirudo status --otel``
     - ``shirudo-keepalive.timer``
   * - ``shirudo-xdp-reconcile.service``
     - ``@bindir@/shirudo upatch reconcile``
     - ``shirudo-xdp-reconcile.timer`` and the udev rule below
   * - ``shirudo-map-export.service``
     - ``@bindir@/shirudo upatch map --all``
     - ``shirudo-map-export.timer``
   * - ``shirudo-bpm-repo-update.service``
     - ``@bindir@/shirudo bpm repo update``, then
       ``@bindir@/shirudo bpm upgrade``
     - ``shirudo-bpm-repo-update.timer``
   * - ``shirudo-bpm-tree-sync.service``
     - ``@bindir@/shirudo bpm tree sync``
     - ``shirudo-bpm-tree-sync.timer``

``@bindir@`` is replaced at build time. It is ``/usr/bin`` in the
packages that ``make -C packaging`` builds and ``$(prefix)/bin``
otherwise, ``/usr/local/bin`` with the default prefix.

shirudo-initrd.service
----------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Value
   * - ``ExecStartPre``
     - ``-mount -o remount,rw /sysroot`` (a failure is ignored)
   * - ``ExecStart``
     - ``@bindir@/shirudo init``: the binary the dracut module copies
       into the initrd at its path on the root file system
   * - ``Type``
     - ``oneshot``, ``RemainAfterExit=yes``
   * - ``ConditionPathExists``
     - ``/etc/initrd-release`` and ``/etc/shirudo/keys/cert.der``. The
       unit is skipped, not failed, when either is missing.
   * - ``After``
     - ``initrd-root-fs.target``, ``tpm2.target``,
       ``systemd-pcrphase-initrd.service``,
       ``systemd-tpm2-setup-early.service``
   * - ``Before``
     - ``initrd.target``, ``initrd-switch-root.target``,
       ``shutdown.target``
   * - ``Conflicts``
     - ``shutdown.target``
   * - ``RequiresMountsFor``
     - ``/sysroot/var/lib/shirudo``
   * - ``DefaultDependencies``
     - ``no``
   * - ``KeyringMode``
     - ``inherit``
   * - ``LimitMEMLOCK``
     - ``infinity``
   * - ``WantedBy``
     - ``initrd.target``

The dracut module ``90shirudo`` installs this unit into the initrd and
enables it there. It never runs in the root file system. No
``OnFailure=`` or failure action is set: when the unit fails, the boot
continues.

shirudo.service
---------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Value
   * - ``ExecStart``
     - ``@bindir@/shirudo init $SHIRUDO_INIT_ARGS``
   * - ``EnvironmentFile``
     - ``-/etc/shirudo/init.env`` (optional)
   * - ``Type``
     - ``oneshot``, ``RemainAfterExit=yes``
   * - ``ConditionPathIsMountPoint``
     - ``/run/shirudo/runtime``: the unit is skipped when the initrd did
       not mount the runtime image
   * - ``After``
     - ``local-fs.target``, ``systemd-tpm2-setup-early.service``,
       ``systemd-pcrnvdone.service``
   * - ``Before``
     - ``sysinit.target``, ``shutdown.target``
   * - ``Conflicts``
     - ``shutdown.target``
   * - ``RequiresMountsFor``
     - ``/var/lib/shirudo``
   * - ``DefaultDependencies``
     - ``no``
   * - ``KeyringMode``
     - ``inherit``
   * - ``LimitMEMLOCK``
     - ``infinity``
   * - ``WantedBy``
     - ``sysinit.target``

Runtime drop-in
~~~~~~~~~~~~~~~

``shirudo-gen-runtime --unit-output <file>`` writes a drop-in for
``shirudo.service`` to ``<file>`` when it builds the runtime image. It
clears ``EnvironmentFile=`` and ``ExecStart=`` and runs ``init`` from the
runtime image. For a static target binary:

.. code-block:: ini

   [Service]
   EnvironmentFile=
   ExecStart=
   ExecStart=/run/shirudo/runtime/usr/bin/shirudo init

For a dynamic binary the drop-in starts the image's own ELF interpreter:

.. code-block:: ini

   [Service]
   EnvironmentFile=
   ExecStart=
   ExecStart=/run/shirudo/runtime<interpreter> --inhibit-cache --library-path <library-path> /run/shirudo/runtime/usr/bin/shirudo init

``<interpreter>`` is the binary's ELF interpreter path and
``<library-path>`` the colon-separated library directories under
``/run/shirudo/runtime`` that the generator copied. With the drop-in
installed, ``/etc/shirudo/init.env`` and ``SHIRUDO_INIT_ARGS`` have no
effect.

The generator writes this drop-in for ``shirudo.service`` only. The
keepalive, reconcile, map-export, repository-update and tree-sync services run
``@bindir@/shirudo``. On a target that enforces, a shirudo binary outside
the runtime image is refused with ``shirudo: image state: Permission
denied`` and exit status 1, so each of these services needs its own
drop-in whose ``ExecStart=`` runs the runtime image's binary. See
:doc:`/operate/deploy/boot-integration`.

shirudo-keepalive.service
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Value
   * - ``ExecStart``
     - ``@bindir@/shirudo status --otel``
   * - ``EnvironmentFile``
     - ``-/etc/shirudo/map-export.env`` (optional)
   * - ``After``
     - ``shirudo.service``
   * - ``TimeoutStartSec``
     - ``2min``
   * - ``LimitMEMLOCK``
     - ``infinity``

The keepalive is sent only when ``map_export.otel_endpoint``,
``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`` or ``OTEL_EXPORTER_OTLP_ENDPOINT``
names an endpoint, and only with its TPM quote: a run whose TPM does not
answer or does not quote fails and sends nothing. See
:doc:`/reference/formats/keepalive`.

A keepalive and a ``bpm tree sync`` do not run at once. Every target
command holds the config operation lock for its whole run, and a sync
holds it until its last operation is applied. A keepalive that starts
during a sync waits up to 30 seconds for the lock; when the sync is
still running then, that run fails and sends nothing, and the next
run of the timer tries again. A sync that fetches and applies for
minutes therefore leaves a gap of about that length in the node's
keepalives, which a backend's threshold for a stale node must allow
for.

shirudo-xdp-reconcile.service
-----------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Value
   * - ``ExecStart``
     - ``@bindir@/shirudo upatch reconcile``
   * - ``After``
     - ``shirudo.service``
   * - ``ConditionPathExists``
     - ``/run/shirudo/bpffs/lsm_link``
   * - ``StartLimitIntervalSec``
     - ``0``, as a burst of new veths would otherwise disable it
   * - ``TimeoutStartSec``
     - ``2min``
   * - ``LimitMEMLOCK``
     - ``infinity``

The rule ``90-shirudo-xdp-reconcile.rules`` in
``/usr/lib/udev/rules.d`` starts it through ``SYSTEMD_WANTS`` when a
network device other than ``lo`` appears. It is not ``RUN+=``, because a
child of ``systemd-udevd`` inherits its seccomp filter and would get no
task mark. A veth peer moving namespace gives the initial namespace no
such event, so the timer is what catches it, within a minute. The timer
runs a pass 60 seconds after the previous one ends rather than more
often because a device that keeps refusing costs a full retry on every
pass. The unit and the rule are not in the initrd. See :doc:`/reference/cli/upatch-reconcile`.

shirudo-map-export.service
--------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Value
   * - ``ExecStart``
     - ``@bindir@/shirudo upatch map --all``
   * - ``EnvironmentFile``
     - ``-/etc/shirudo/map-export.env`` (optional)
   * - ``ConditionPathExists``
     - ``/run/shirudo/bpffs/lsm_link``
   * - ``After``
     - ``shirudo.service``
   * - ``TimeoutStartSec``
     - ``5min``
   * - ``LimitMEMLOCK``
     - ``infinity``

The destinations come from the ``map_export.*`` settings, see
:doc:`/reference/configuration`.

shirudo-bpm-repo-update.service
-------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Value
   * - ``ExecStart``
     - ``-@bindir@/shirudo bpm repo update`` (a failure is ignored), then
       ``@bindir@/shirudo bpm upgrade``
   * - ``EnvironmentFile``
     - ``-/etc/shirudo/bpm/environment`` (optional)
   * - ``Wants``
     - ``network-online.target``
   * - ``After``
     - ``network-online.target``, ``shirudo.service``
   * - ``RequiresMountsFor``
     - ``/etc/shirudo/bpm``, ``/var/lib/shirudo``
   * - ``TimeoutStartSec``
     - ``30min``
   * - ``LimitMEMLOCK``
     - ``infinity``

``bpm repo update`` refreshes the index of every repository in
``registries.d``. ``bpm upgrade`` then installs, for every package
installed from a repository, the highest version in its cached index
when that version is newer than the installed one. A package pulled
directly is left alone. If an installed package's repository certificate
cannot be read or its cached index needs a refresh, ``bpm upgrade`` skips
that repository's packages, continues with the others and exits 1. See
:doc:`/operate/run/deliver-packages`.

shirudo-bpm-tree-sync.service
-----------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Value
   * - ``ExecStart``
     - ``@bindir@/shirudo bpm tree sync``
   * - ``EnvironmentFile``
     - ``-/etc/shirudo/bpm/environment`` (optional)
   * - ``Wants``
     - ``network-online.target``
   * - ``After``
     - ``network-online.target``, ``shirudo.service``
   * - ``RequiresMountsFor``
     - ``/etc/shirudo/bpm``, ``/var/lib/shirudo``
   * - ``TimeoutStartSec``
     - ``30min``
   * - ``LimitMEMLOCK``
     - ``infinity``

``bpm tree sync`` exits 0 without contacting a registry when no
``upatch-tree.conf`` is configured.

Timers
------

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Timer
     - Schedule
   * - ``shirudo-keepalive.timer``
     - ``OnBootSec=5s``, ``OnUnitInactiveSec=60s``, ``AccuracySec=1s``
   * - ``shirudo-xdp-reconcile.timer``
     - ``OnBootSec=5s``, ``OnUnitInactiveSec=60s``, ``AccuracySec=1s``
   * - ``shirudo-map-export.timer``
     - ``OnBootSec=5s``, ``OnUnitInactiveSec=5s``, ``AccuracySec=1s``
   * - ``shirudo-bpm-repo-update.timer``
     - ``OnBootSec=0s``, ``OnUnitInactiveSec=60s``, ``AccuracySec=1s``
   * - ``shirudo-bpm-tree-sync.timer``
     - ``OnBootSec=60s``, ``OnUnitActiveSec=60s``, ``Persistent=true``,
       ``AccuracySec=1s``

Each timer starts the service of the same name and is
``WantedBy=timers.target``. ``OnUnitInactiveSec=`` counts from the end of
the previous run, ``OnUnitActiveSec=`` from its start.

Memory lock
-----------

Every ``shirudo`` and ``shirudo-build`` process calls ``mlockall()``
before it dispatches a command and exits with status 1 when that fails
(``hardening: cannot lock process memory``). Every service sets
``LimitMEMLOCK=infinity`` for that reason.

Enablement
----------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Installer
     - What it enables
   * - Target ``.deb`` and ``.rpm``
     - On install: ``systemctl enable`` of ``shirudo.service`` and the
       five timers, for the next boot, and ``udevadm control --reload``.
       Nothing is started. On removal: ``disable --now`` of the five
       timers and ``disable`` of
       ``shirudo.service``.
   * - Target tarball (``install.sh``)
     - ``systemctl daemon-reload`` only.
   * - dracut module ``90shirudo``
     - ``shirudo-initrd.service``, inside the initrd it builds.

The operator package installs no units.

Related
-------

- :doc:`/reference/environment` for the variables the
  ``EnvironmentFile=`` files set
- :doc:`/reference/configuration` for the settings the services
  read
- :doc:`/reference/cli/init`, :doc:`/reference/cli/status`,
  :doc:`/reference/cli/upatch-map` and :doc:`/reference/cli/bpm` for the
  commands the services run
- :doc:`/operate/deploy/boot-integration` for installing the units with the
  runtime image
