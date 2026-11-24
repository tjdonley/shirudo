..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Deliver packages
================

Targets pull signed packages from OCI registries. You publish a package
on the operator host, and every target that follows the repository
installs or upgrades it on its own. This page shows how to point targets
at a repository, how to install, upgrade and remove packages by hand,
and how the timers and the upatch tree deliver them without you.

How a package reaches a target
------------------------------

Delivery is a pull in four steps, which Figure 1 shows together with
the upatch tree:

#. On the operator host, ``shirudo bpm push`` publishes the package and
   a signed entry in the repository index
   ``<namespace>/bpm-index:stable``.
#. On the target, ``shirudo bpm repo update`` fetches that index from
   each repository, verifies its signature against the repository's
   certificate and caches it under
   ``/var/lib/shirudo/bpm/repos/<name>/index.cache``.
#. ``shirudo bpm upgrade`` installs, for every package installed from a
   repository, the highest version in the cached index that is newer
   than the installed one.
#. The install checks the package archive against the digest in the
   index, refuses a package whose ``cert.der`` does not carry the public
   key of ``/var/lib/shirudo/keys/cert.der``, and loads each upatch the
   way ``shirudo upatch load`` does. The kernel verifies each loader's
   signature against the ``.bpf`` keyring, and shirudo measures each load
   into the TPM register.

``shirudo-bpm-repo-update.service`` runs ``bpm repo update`` and then
``bpm upgrade``. Its timer starts it at boot and again 60 seconds after
each run ends. A version you push to a repository index therefore
reaches every target that follows the repository about a minute later,
with nobody logged in. Treat every push to an index as a fleet-wide
rollout.

.. figure:: /images/operate-package-delivery.svg
   :alt: The operator host builds and pushes a package, a signed index
         entry and, optionally, a signed tree operation to an OCI
         registry. On the target, timers update the indexes, upgrade
         the packages and sync the tree; each load is checked by the
         kernel and measured by the TPM.

   Figure 1. How a package and a tree operation reach a target.

What is configured where
------------------------

A target reads its package inputs from the signed config image, not from
the host's ``/etc/shirudo``. Copies of these files on the host root file
system have no effect while a config image is active.

.. list-table::
   :header-rows: 1
   :widths: 30 40 30

   * - Input
     - Location on the target
     - How you change it
   * - Repository definitions
     - ``etc/shirudo/bpm/registries.d/<name>.conf`` in the config image
     - New signed config, ``shirudo image update``
   * - Repository certificates
     - ``etc/shirudo/bpm/keys/`` in the config image
     - New signed config, ``shirudo image update``
   * - Subscription to the upatch tree
     - ``etc/shirudo/bpm/upatch-tree.conf`` in the config image
     - New signed config, ``shirudo image update``
   * - Node labels for tree selectors
     - ``etc/shirudo/node.labels`` in the config image
     - New signed config, ``shirudo image update``
   * - Hosts allowed classical TLS key exchange
     - ``tls.classical_hosts`` in the runtime image's
       ``etc/shirudo/shirudo.conf``
     - New runtime image and a reboot
   * - Registry credentials and transport
     - ``/etc/shirudo/bpm/environment`` on the host
     - Root on the target, no signature
   * - Installed packages
     - ``/var/lib/shirudo/bpm/state.json``
     - ``bpm install``, ``bpm upgrade``, ``bpm uninstall``

While a config image is active, the target refuses local changes to
these inputs. ``bpm config register add``, ``remove`` and ``rm`` exit 1
with ``image mode: change repository definitions and keys in a signed
config image, then run `shirudo image update```. ``bpm key add`` exits 1
with ``image mode: add vouched BPF signers to the signed config selected
for boot and reboot to enroll them``.

systemd reads ``/etc/shirudo/bpm/environment`` for the two package
services. The file can set registry credentials (``BPM_OCI_USERNAME``
with ``BPM_OCI_PASSWORD``, ``BPM_OCI_BEARER_TOKEN``,
``REGISTRY_AUTH_FILE``, ``DOCKER_CONFIG``), cleartext transport
(``BPM_OCI_SCHEME=http``) and an extra CA certificate
(``BPM_OCI_CA_FILE``). It is host state outside the signed config, and
root on the target can change it. The signatures on the index, the
package and the upatches do not depend on it, but the transport does.
:doc:`/reference/environment` lists every variable, and
:doc:`/security/threat-model` describes what root on the target can do
with it.

If you keep the auth file or the CA certificate under ``/etc/shirudo``,
make the file and each directory its path leads through root's and not
writable by group or others, and each symbolic link on the path root's.
A link of root's to the distribution's CA certificates passes;
:ref:`trusted-files` gives the rules.

Before you begin
----------------

- An initialized target (:doc:`/operate/deploy/initialize`) whose services run
  the runtime binary (:ref:`unit-drop-ins`).
- On the target, ``shirudo`` stands for the runtime image's binary,
  ``/run/shirudo/runtime/usr/bin/shirudo`` (:ref:`runtime-invocation`).
- A package published to a repository (:doc:`/start/guides/publish-package`).
- On the operator host, the source directory of the target's config
  image and the key that signs config images.

Add a repository
----------------

#. In the config source directory, create
   ``etc/shirudo/bpm/registries.d/<name>.conf``:

   .. code-block:: text

      endpoint = oci://<registry-host>
      key_file = /etc/shirudo/bpm/keys/<name>.der

   ``index_repository`` is optional. If omitted, shirudo uses
   ``<name>/bpm-index``; use the package namespace as ``<name>`` to match
   ``bpm push``. Set the field explicitly when the source name differs.

   ``<name>`` is the repository name that ``bpm install`` uses. When the
   default index location is used, it must also be the package namespace.
   ``<registry-host>`` is the registry's host name with an optional port
   and no path. ``index_repository`` names the index repository. Its
   namespace must match the namespace of the package repository passed to
   ``bpm push``. ``key_file`` names a certificate inside the config image.
   The target refuses any other absolute path.

#. Copy the certificate whose key signs the repository index, the one
   you pass to ``bpm push``, to ``etc/shirudo/bpm/keys/<name>.der`` in
   the same directory.

#. Build, sign and activate the config, as described in
   :ref:`deliver-packages-config-update`.

#. List the repositories the target reads:

   .. code-block:: console

      target# shirudo bpm config register list

   The command prints ``Registered sources:`` and one repository name
   per line, or ``none``.

#. Fetch the repository's index now instead of waiting for the timer:

   .. code-block:: console

      target# shirudo bpm repo update <name>

   The command prints nothing when it succeeds. When it fails, it prints
   ``bpm repo update: <reason>`` and exits 1. Without ``<name>`` it
   updates every repository, continues past one that fails and exits 1
   at the end. If a refresh fails, the target can use its last verified
   index for the same source, endpoint, index repository and certificate.
   Refresh successfully after changing any of them, including replacing
   the certificate at the same path. A target upgraded from a version
   that cached only ``index.json`` also needs one successful refresh.

.. _deliver-packages-config-update:

Change the signed config
------------------------

Every change to repositories, the tree subscription, node labels and
export settings is a new signed config image that the target activates
while it runs.

#. Build and sign the image from the config source directory:

   .. code-block:: console

      operator$ /usr/libexec/shirudo/gen-image/shirudo-gen-image \
          --source <config-root> --output <prefix> \
          --keys-dir <config-keys-dir> --kind config

   ``<config-root>`` is the source directory. It must contain
   ``etc/shirudo/shirudo.conf``, which accepts only ``eventlog.max_bytes``
   and ``map_export.*`` keys, and it must not contain symbolic links or
   special files. ``<prefix>`` is the output path without a suffix: the
   command writes ``<prefix>.img``, ``<prefix>.verity``,
   ``<prefix>.roothash`` and ``<prefix>.p7s`` and refuses to replace an
   existing file. ``<config-keys-dir>`` holds the key whose certificate
   the runtime image lists in a ``config.verification_key`` entry. The path is
   the operator package's. From a checkout, run
   :src:`tools/gen-image/shirudo-gen-image` and add ``--builder`` with the
   path of ``shirudo-build``.

#. Verify the bundle offline:

   .. code-block:: console

      operator$ shirudo image verify <prefix> --cert <config-cert>

   ``<config-cert>`` is the config verification certificate in DER. The
   command prints the root hash.

#. Copy the four files to the target, or serve them over HTTPS under one
   URL prefix.

#. Activate the config on the target:

   .. code-block:: console

      target# shirudo image update <prefix>

   ``<prefix>`` is the local path prefix of the four files, or their
   ``https://`` URL prefix. The command fetches and verifies the bundle,
   extends the config PCR and switches to the new config.

#. Check the activation:

   .. code-block:: console

      target# shirudo image status
      Config root hash:      6d5ed552f4487728d1ccec8604ddb44b66b18e3430614c20bb4d284995f99f63
      PCR:                   14
      Sequence:              1
      TPM reset count:       1
      Restart count:         0
      Pending:               no
      Consistent:            yes

   This output is from a target that runs its boot config. After an
   update, ``Config root hash`` is the root that ``image verify`` printed
   and ``Sequence`` is higher. ``Pending`` must be ``no`` and
   ``Consistent`` must be ``yes``. The command exits 1 otherwise, and
   ``--json`` prints the same fields as one JSON document. If an
   activation stays pending, follow :doc:`/operate/maintain/backup-recovery`.

Install a package
-----------------

#. Install the package from a repository:

   .. code-block:: console

      target# shirudo bpm install <name>/<package>

   ``<name>`` is the repository name and ``<package>`` the package name.
   Without a version, the command installs the highest version in the
   cached index. Append ``@<version>`` to choose one. The command loads
   each upatch of the package and prints what ``shirudo upatch load``
   prints.

#. Check that the package is installed:

   .. code-block:: console

      target# shirudo bpm list

   The command prints ``Installed packages:``, a header and one line per
   installed package: its name, its version and the repository it came
   from, or ``direct`` for an ``oci://`` install. With no package
   installed it prints ``none``.

#. Check that its upatches are loaded:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        NAME                      LOADED  TYPE    KIND  PAYLOAD
        shirudo-test-basic        yes     load    bpf   8aee7072a1a15e4d..

   This target holds one upatch, loaded by hand. A package's upatches
   appear the same way, one line each.

``bpm install`` does nothing and exits 0 when a package of that name is
already installed, whatever its version. The repository timer moves an
installed package to the highest version in its index at its next run,
so ``@<version>`` does not hold a package at that version.

A package can also be installed straight from a registry reference:

.. code-block:: console

   target# shirudo bpm install oci://<registry-host>/<repository>:<tag>

No signed index covers such an install: the registry decides which
package the tag names. Its upatches still load only when a key in the
``.bpf`` keyring signed them. ``bpm upgrade`` leaves direct installs
alone.

Upgrade packages
----------------

#. Refresh the cached indexes:

   .. code-block:: console

      target# shirudo bpm repo update

#. Upgrade every package that has a newer version in its index:

   .. code-block:: console

      target# shirudo bpm upgrade

   ``bpm upgrade`` reads only the cached indexes. For each package it
   runs the old version's unload directives in reverse name order and
   then loads the new version's upatches. When a load fails, it unloads
   what it loaded, tries to load the old version again and exits 1.
   Packages it upgraded before the failure stay upgraded.

#. Check the versions with ``shirudo bpm list``.

The repository timer runs both steps every minute, so you need them only
to upgrade before the timer does.

Uninstall a package
-------------------

#. Uninstall the package:

   .. code-block:: console

      target# shirudo bpm uninstall <package>

   The command runs the package's unload directives in reverse name
   order, removes the package's files and removes it from the installed
   state. Each unload is measured. When an unload fails, the command
   prints ``bpm uninstall: unload <path> failed`` and stops.

#. Check that ``shirudo bpm list`` no longer lists it and that
   ``shirudo upatch list`` no longer shows its upatches.

Removing a package from its index does not uninstall it from targets:
``bpm upgrade`` skips an installed package that its index no longer
lists.

Follow the upatch tree
----------------------

The upatch tree is a signed, ordered list of ``add`` and ``delete``
operations that you append on the operator host with
``shirudo bpm tree append``. Each operation can carry selectors on the
kernel release, kernel build ID, architecture, kernel configuration and
node labels, so one publication serves a mixed fleet.

#. In the config source directory, create
   ``etc/shirudo/bpm/upatch-tree.conf``:

   .. code-block:: text

      endpoint = oci://<registry-host>/<repository>
      reference = <reference>

   ``<repository>`` is the tree's repository and ``<reference>`` the
   tag ``bpm tree append`` published to, ``stable`` unless you chose
   another.

#. If operations select on labels, write the target's labels to
   ``etc/shirudo/node.labels``, one ``<key>=<value>`` per line.

#. Build, sign and activate the config
   (:ref:`deliver-packages-config-update`).

#. Preview what a sync would apply:

   .. code-block:: console

      target# shirudo bpm tree sync --dry-run

   The command prints a JSON report with the counts ``selected``,
   ``skipped``, ``applied`` and ``module_skipped`` and the sequence
   number ``last_seq`` the target has reached. A dry run changes
   nothing.

``shirudo-bpm-tree-sync.timer`` runs ``bpm tree sync`` 60 seconds after
boot and every 60 seconds after that. Without a tree configuration the
command exits 0 and does nothing. Each applied operation is measured.

Keep these rules of the tree in mind. Figure 2 shows them on one
publication:

- A sync moves the target's cursor past an operation whose selectors do
  not match. The target never applies that operation later, even when
  its labels or kernel change. A selector the target cannot evaluate,
  because its kernel config or its node labels cannot be read, stops
  the sync with ``selector_evaluate`` and leaves the cursor on the
  operation, so the next sync tries again.
- An ``add`` whose attach target is in a kernel module that is not
  loaded is recorded as ``skipped: module not loaded``, and the cursor
  moves past it.
- The target verifies tree publications against the BPF signers of the
  active config: the runtime image's primary certificate and the
  certificates the config vouches for, less the ones it revokes.
  :doc:`/operate/maintain/keys` describes the signer set.

.. figure:: /images/operate-tree-selectors.svg
   :alt: A target with kernel 7.4.0 on x86_64 and the label env=prod
         applies the operations with no selector or a matching
         kernel release, skips those for aarch64 and for env=canary,
         and ends with last_seq at the last operation.

   Figure 2. One target going through a tree publication. Skipped
   operations stay skipped.

Timers and locks
----------------

.. list-table::
   :header-rows: 1
   :widths: 34 34 32

   * - Timer
     - Runs
     - When
   * - ``shirudo-bpm-repo-update.timer``
     - ``bpm repo update``, then ``bpm upgrade``
     - At boot, then 60 s after each run ends
   * - ``shirudo-bpm-tree-sync.timer``
     - ``bpm tree sync``
     - 60 s after boot, then every 60 s

Both services run the host's ``shirudo`` unless you installed the
runtime drop-ins (:ref:`unit-drop-ins`). An enforcing target refuses
that binary, so without the drop-ins nothing is delivered.

``bpm install``, ``upgrade``, ``uninstall``, ``repo update`` and
``tree sync`` take ``/var/lib/shirudo/locks/bpm.lock`` and wait for it
without a time limit. Every ``shirudo`` command on a target also holds
the config operation lock for its whole run, and a command that waits
longer than 30 seconds for it fails. A long download therefore delays
the status keepalive and the map export, and a keepalive can fail while
it runs. :doc:`/operate/troubleshoot/troubleshooting` has the message.

Every command except ``status`` and ``image status`` is refused while a
config activation is pending, ``bpm uninstall`` included. :doc:`/operate/maintain/backup-recovery`
describes that state.

Next steps
----------

- :doc:`/start/guides/publish-package` to publish a package
- :doc:`/upatches/publish/publishing` for packages, indexes and the tree on the
  operator side
- :doc:`/operate/run/telemetry` to export what the installed upatches collect
- :doc:`/reference/cli/bpm` for every ``bpm`` option
- :doc:`/reference/formats/bpm-formats` for the index and package
  formats
- :doc:`/reference/formats/upatch-tree` for the tree format
  formats
