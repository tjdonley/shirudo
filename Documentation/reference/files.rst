..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Files, paths and xattrs
=======================

The files, directories, pins and extended attributes shirudo reads and
writes. In the Protection columns, "seal" means the inode carries the
``security.bpf.shirudo`` label (see :doc:`/internals/seal`), "dm-verity"
means a read-only mount of a verified image and "bpffs" means the
guards of the private bpffs.

Operator host
-------------

.. list-table::
   :header-rows: 1
   :widths: 38 20 10 32

   * - Path
     - Written by
     - Mode
     - Purpose
   * - ``/var/lib/shirudo/keys/``
     - ``genkey``
     - ``0700``
     - Default keys directory. ``--keys-dir`` and ``SHIRUDO_KEYS_DIR``
       select another.
   * - ``<keys-dir>/signing_key.pem``
     - ``genkey``
     - ``0600``
     - ML-DSA-87 private key, PEM. ``shirudo-build`` refuses a key whose
       mode is not exactly ``0600``.
   * - ``<keys-dir>/cert.der``
     - ``genkey``
     - ``0600``
     - Self-signed X.509 certificate of the signing key, DER.
   * - ``<keys-dir>/signing_key.pem.new``, ``cert.der.new``,
       ``signing_key.pem.old``
     - ``genkey --force``
     - ``0600``
     - Transient during a key replacement.
   * - ``/var/lib/shirudo/upatches/<name>.upatch``
     - none
     - none
     - Read by ``shirudo build --unload <name>`` without
       ``--payload-sha256`` to take the expected payload from a local
       archive.
   * - ``./vmlinux.h``, ``./vendor/linux/vmlinux.h``,
       ``<sharedir>/shirudo/vmlinux.h``
     - none
     - none
     - Searched in this order when ``--vmlinux`` is not given.
   * - ``/usr/bin/clang``, ``/usr/lib/llvm-23/bin/clang`` in the Debian
       package
     - none
     - none
     - The compiler ``shirudo-build`` executes for ``.bpf.c`` input,
       clang 23.
   * - ``$(bindir)/shirudo-quote-check``
     - operator package, ``make install-operator``
     - ``0755``
     - Checks keepalive quotes for a telemetry backend. A static PIE.
       It reads standard input alone and writes no file. See
       :doc:`/reference/cli/quote-check`.
   * - ``/tmp/shirudo-build-XXXXXX.bpf.o``
     - ``build``
     - none
     - Temporary object, removed after packaging.
   * - ``$TMPDIR/shirudo-bpm-build.XXXXXX/``
     - ``bpm build``
     - ``0700``
     - Staging directory of a package build (``/tmp`` when ``TMPDIR``
       is unset), removed when the build ends.
   * - ``/etc/shirudo/shirudo.conf``
     - administrator
     - none
     - Operator settings, such as ``tls.classical_hosts``. See
       :doc:`/reference/configuration`.

Output files the caller names: ``.upatch`` artifacts and ``.vouch``
files with mode ``0644``, ``.bee`` packages with mode ``0600``.

Target persistent state
-----------------------

Everything under ``/var/lib/shirudo`` on the state file system is
sealed. The first ``init`` labels every regular file and directory there.
From then on shirudo labels what it creates, and ignores an entry without
the label as foreign. In the initrd, ``init`` binds
``/sysroot/var/lib/shirudo`` writable over ``/var/lib/shirudo``.

.. list-table::
   :header-rows: 1
   :widths: 36 20 9 35

   * - Path
     - Written by
     - Mode
     - Purpose
   * - ``/var/lib/shirudo/``
     - ``init``
     - ``0700``
     - State root.
   * - ``keys/cert.der``
     - installer, ``bpm key add``
     - none
     - Checked by the ``cert_on_disk`` pre-flight outside the initrd, and
       the default certificate the dracut module copies into the initrd.
       On a running target the certificates come from the runtime and
       config images.
   * - ``keys/<fingerprint>.der``
     - ``bpm key add``
     - ``0644``
     - A certificate installed without a config image. ``bpm key add``
       is refused on a target with a config image.
   * - ``keys/trusted/``, ``keys/revoked/``
     - ``keys add`` (``trusted/``)
     - none
     - Trusted and revoked sets read when no config image is mounted.
       ``keys add`` is refused on a target with a config image.
   * - ``upatches/<name>.upatch``
     - ``upatch load``
     - ``0644``
     - Archive of every loaded upatch, restored by ``init`` at boot.
       ``upatch unload`` and a revocation purge remove it.
   * - ``eventlog``
     - measuring commands
     - ``0600``
     - Append-only eventlog, one JSON record per line. See
       :doc:`/reference/eventlog`.
   * - ``locks/bpm.lock``
     - ``bpm``
     - ``0600``
     - Lock of ``repo update``, ``tree sync``, ``install``,
       ``uninstall`` and ``upgrade``.
   * - ``bpm/state.json``
     - ``bpm install``, ``uninstall``, ``upgrade``
     - ``0600``
     - Installed packages.
   * - ``bpm/repos/<source>/index.cache``
     - ``bpm repo update``
     - ``0600``
     - Verified package index with its source name, endpoint, index
       repository and the SHA-256 of its signing certificate.
   * - ``bpm/staging/<name>-<version>.bee``
     - ``bpm install``, ``upgrade``
     - ``0600``
     - Package download before it is verified and extracted.
   * - ``bpm/packages/<name>/<version>/``
     - ``bpm install``, ``upgrade``
     - none
     - Extracted package: ``cert.der``, ``upatches/*.upatch`` and the
       unload directives.
   * - ``bpm/packages/<name>/<name>-<version>.bee``
     - ``bpm install``, ``upgrade``
     - ``0600``
     - The installed package archive.
   * - ``bpm/upatch-tree/state.json``
     - ``bpm tree sync``
     - ``0600``
     - Tree cursor: tree id, last sequence number and projection root,
       and the generation, manifest digest and head of the publication
       the target last accepted.
   * - ``bpm/upatch-tree/tree-eventlog``
     - ``bpm tree sync``
     - ``0600``
     - Append-only record of applied tree operations.
   * - ``bpm/upatch-tree/outcomes``
     - ``bpm tree sync``
     - ``0600``
     - One line for every tree operation the target processed, applied
       or not, with its outcome and the roots after it. Never pruned.
   * - ``bpm/upatch-tree/pending.json``
     - ``bpm tree sync``
     - ``0600``
     - The operation in progress, removed when it completes or when
       the next sync finds it at or below the cursor.
   * - ``bpm/upatch-tree/artifacts/<layer-digest>.upatch``
     - ``bpm tree sync``
     - ``0600``
     - Fetched artifacts, named by their OCI layer digest.
   * - ``bpm/upatch-tree/status/<id>``
     - ``bpm tree sync``
     - ``0600``
     - ``skipped: module not loaded`` for an ``add`` operation whose
       target is absent.
   * - ``config-update/lock``, ``state``, ``events``
     - ``init``, ``image update``
     - ``0600``
     - Config activation record and its event history.
   * - ``config-update/next-boot``
     - ``image stage``, ``init``
     - ``0600``
     - Candidate config for the next TPM boot and its parent activation
       sequence and boot counts. Removed on cancellation, successful
       boot initialization or a live update to a different root.
   * - ``images/<root-hash>.img``, ``.verity``, ``.roothash``, ``.p7s``
     - ``image update``, ``image stage``
     - ``0600``
     - Fetched config images, named by their dm-verity root hash.
   * - ``images/incoming-XXXXXX/``
     - ``image update``, ``image stage``
     - none
     - Staging directory of a fetch.

The paths in the table are relative to ``/var/lib/shirudo/``.

Target per-boot state
---------------------

``init`` creates ``/run/shirudo`` with mode ``0700``. When it lies on the
same file system as ``/run``, ``init`` mounts a private ``tmpfs`` there
(``nosuid``, ``nodev``, ``noexec``, 16 MiB) and labels it. systemd
carries ``/run`` from the initrd into the root file system.

.. list-table::
   :header-rows: 1
   :widths: 36 18 16 30

   * - Path
     - Written by
     - Protection
     - Purpose
   * - ``/run/shirudo/eventlog.pending``
     - ``init`` in the initrd
     - seal, ``0600``
     - The initrd's eventlog record. The next append on the root file
       system adopts it into ``/var/lib/shirudo/eventlog`` and removes
       it.
   * - ``/run/shirudo/bpffs/``
     - ``init``
     - bpffs
     - Private bpffs (``mode=0700``, ``nosuid``, ``nodev``,
       ``noexec``) holding every pin. Its root is also the register
       lock: measuring commands ``flock`` it from each register extend to
       its eventlog append, and a load or an unload from before it
       touches the pins.
   * - ``/run/shirudo/runtime/``
     - ``init``
     - dm-verity
     - The runtime image, mounted read-only, ``nodev``, ``nosuid``. The
       dm-verity mapping is ``shirudo-runtime``.
   * - ``/run/shirudo/config/``
     - ``init``, ``image update``
     - dm-verity
     - The active config image, mounted read-only, ``nodev``,
       ``nosuid``, ``noexec``.
   * - ``/run/shirudo/config-candidate/``
     - ``image update``
     - dm-verity
     - A config image being activated. Its mapping is
       ``shirudo-config-<root-hash>``.
   * - ``/run/shirudo-java/<name>.jar``
     - ``upatch load``, ``init``
     - seal, ``0644`` in a ``0755`` directory
     - The agent jar of a loaded Java upatch, readable by every JVM.
       ``init`` makes and labels the directory, and writes each jar
       from its archive at boot. An unload, a purge and every upatch
       command replace a jar whose archive is not a Java load with one
       whose agent does nothing, which stays until the next boot.
   * - ``/run/environment.d/shirudo.conf``
     - ``upatch load``, ``upatch unload``, ``init``
     - none, ``0644``
     - A ``-javaagent`` for each jar in ``/run/shirudo-java`` whose
       archive is a Java load, in name order, appended to
       ``JAVA_TOOL_OPTIONS``. Rewritten only when that changes it, and
       removed when there is none. It lasts as long as the jars it names. Root can change it.
       systemd's user managers read it; see
       :doc:`/upatches/write/java-agents`.

Runtime image
~~~~~~~~~~~~~

``shirudo-gen-runtime`` lays out the runtime image. Paths are relative
to ``/run/shirudo/runtime/``.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Path
     - Content
   * - ``usr/bin/shirudo``
     - The runtime binary. ``shirudo.service`` runs it through the
       generated drop-in.
   * - ``usr/bin/<name>``
     - Binaries added with ``--extra-binary``.
   * - ``etc/shirudo/shirudo.conf``
     - Runtime settings.
   * - ``etc/shirudo/config-cert.der``
     - First config verification certificate. Additional
       ``--config-cert`` inputs become ``config-cert-2.der`` and on.
       The bootstrap's repeated ``config.verification_key`` entries name
       all allowed certificates.
   * - ``keys/cert.der``
     - The initial BPF signing certificate.
   * - Library paths
     - The interpreter and shared libraries of a dynamically linked
       binary.

Config image
~~~~~~~~~~~~

Paths are relative to ``/run/shirudo/config/``. On a target with a
config image, shirudo reads these instead of the host files of the same
name under ``/etc/shirudo``.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Path
     - Content
   * - ``etc/shirudo/shirudo.conf``
     - Settings the config image may carry.
   * - ``etc/shirudo/bpm/registries.d/<source>.conf``
     - Package repositories.
   * - ``etc/shirudo/bpm/keys/``
     - Repository certificates.
   * - ``etc/shirudo/bpm/upatch-tree.conf``
     - upatch tree source.
   * - ``etc/shirudo/node.labels``
     - Labels that tree selectors match.
   * - ``keys/trusted/``
     - Vouched BPF signing certificates.
   * - ``keys/revoked/``
     - Revoked certificates.

See :doc:`/reference/configuration` for the keys of each file.

Private bpffs pins
------------------

Every pin lives under ``/run/shirudo/bpffs/``. The ``lsm/inode_unlink``
guard refuses removing a pin (counter ``PinUnlink``) and the mount guards
refuse unmounting or covering the bpffs (``BpffsUmount``). A task without
runtime authority cannot open a pin that is not a directory, by path or
by ``BPF_OBJ_GET`` (``ObjGet``). Directories stay listable.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Pin
     - Content
   * - ``lsm_link``
     - Link of ``lsm/bpf``, the ``bpf()`` admission hook. Its presence
       makes the ``LsmAttached`` condition report ``OK``.
   * - ``bpf2_bpf_map_link``, ``bpf2_bpf_prog_link``, ``bpf2_bpf_prog_load_link``,
       ``bpf2_inode_unlink_link``, ``bpf2_inode_setxattr_link``,
       ``bpf2_inode_removexattr_link``, ``bpf2_key_permission_link``,
       ``bpf2_tpm_command_link``
     - Links of the other admission and gate hooks.
   * - ``bpf2_sb_umount_link``, ``bpf2_move_mount_link``,
       ``bpf2_sb_mount_link``, ``bpf2_sb_remount_link``,
       ``bpf2_file_open_link``
     - Links of the mount and bpffs guards.
   * - ``bpf2_task_prctl_link``, ``bpf2_bprm_check_security_link``,
       ``inode_rmdir_link``, ``bpf2_inode_rename_link``,
       ``inode_mkdir_link``, ``inode_symlink_link``, ``inode_link_link``,
       ``kernel_load_data_link``, ``kernel_read_file_link``,
       ``locked_down_link``
     - Links of the exec identity, directory entry and kexec guards.
   * - ``file_ioctl_link``, ``file_ioctl_compat_link``,
       ``bdev_integrity_link``, ``bdev_free_link``
     - Links of the ioctl guard and the dm-verity device recorders.
   * - ``seal_*_link``
     - Links of the seal hooks, one per hook, such as
       ``seal_file_open_link`` and ``seal_mmap_link``.
   * - ``identity``
     - Map ``shirudo_bpffs_sb``: the frozen record of this boot, such
       as the ``.bpf`` keyring serial, the runtime root hash and the NV
       index.
   * - ``tamper``
     - Map ``shirudo_tamper``: the tamper counters. See
       :doc:`/security/tamper-counters`.
   * - ``integrity``
     - Map ``shirudo_integrity``: the integrity counters. See
       :doc:`/security/integrity-counters`.
   * - ``task_authority``, ``config_roots``
     - Task storage maps of runtime authority and expected config roots.
   * - ``task_policy``, ``socket_policy``
     - Maps ``shirudo_task_policy`` and ``shirudo_sock_policy``: the
       policy bits of each task and of each socket it creates, which
       policy-label upatches read.
   * - ``devices``
     - Map of the dm-verity devices shirudo set up, with their root
       hashes.

Pins of a upatch
~~~~~~~~~~~~~~~~

Each loaded upatch has a directory ``upatches/<bpffs-name>/`` in the
private bpffs. ``<bpffs-name>`` is the upatch name with every ``.``
written as ``~d``.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Pin
     - Content
   * - ``link``
     - The link of the only attached program, when the artifact has no XDP.
   * - ``link_<n>``
     - Attachment ``<n>`` when there are several programs or the artifact
       contains XDP. XDP can produce multiple links per program, ordered
       by program and then ifindex; skipped devices consume no pin number.
   * - ``xdp_prog_<i>``
     - XDP program ``<i>`` of the artifact's signed metadata. It holds the
       program loaded whatever devices it is attached to.
   * - ``test``
     - A program with the test-run role.
   * - ``serializers/<map>``
     - The serializer program of ``<map>``.
   * - ``maps/<map>``
     - The upatch's maps, less those whose name contains ``.`` or starts
       with ``obs_i_``.

Extended attributes
-------------------

.. list-table::
   :header-rows: 1
   :widths: 30 25 45

   * - Name
     - On
     - Value and rules
   * - ``security.bpf.shirudo``
     - Every regular file and directory of shirudo's writable state:
       ``/var/lib/shirudo``, ``/run/shirudo``, ``/run/shirudo-java``.
     - 64 lowercase hex characters, the SHA-256 of the attribute name,
       the same on every build. The seal treats any value as the label.
       Only a task with runtime authority may set it (``SealLabel``).
       A file created in a labeled directory receives the label at
       creation.
   * - ``security.bpf.shirudo.policy``
     - Executable inodes carrying task policy bits.
     - Exactly 8 bytes, the target-native representation of a ``__u64``
       bitset. Exec ORs the original file and interpreter values into
       task storage. Only a task with runtime authority may set, update
       or remove it (``SealLabel``).
   * - ``security.bpf.shirudo.ancestor``
     - Each directory above ``/var/lib/shirudo`` on its file system,
       ``/var/lib`` and ``/var`` when the state is on the root file
       system.
     - ``1``, set by the run of ``init`` that brings enforcement up. The
       seal refuses a task without runtime authority a rename of or over
       a directory that carries it (``SealRename``), and the setting or
       removal of it on any inode (``SealLabel``).
   * - ``security.bpf.shirudo.payload``
     - Each ``upatches/<bpffs-name>/`` directory in the private bpffs.
     - 32 bytes, the ``payload_sha256`` of the loaded upatch. Set after
       attach and pin, read by ``upatch unload`` for the
       ``payload_mismatch`` check. The bpffs guards refuse setting or
       removing it to any other task (``PinXattr``).

Host configuration
------------------

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Path
     - Use
   * - ``/etc/shirudo/shirudo.conf``
     - On the root file system: the source of the initrd's bootstrap
       file and the settings of a host without images. In the initrd:
       the bootstrap file. See :doc:`/reference/configuration`.
   * - ``/etc/shirudo/keys/cert.der``, ``/etc/shirudo/keys/trusted/``
     - In the initrd only: the certificates the dracut module copies in.
   * - ``/etc/shirudo/bpm/registries.d/<source>.conf``
     - Repository of a host without a config image. Written by ``bpm
       config register add`` with mode ``0644``.
   * - ``/etc/shirudo/bpm/keys/<source>.der``
     - Repository certificate of a host without a config image, ``0644``.
   * - ``/etc/shirudo/bpm/upatch-tree.conf``
     - Tree source of a host without a config image.
   * - ``/etc/shirudo/node.labels``
     - Node labels of a host without a config image.
   * - ``/etc/shirudo/init.env``
     - ``EnvironmentFile`` of ``shirudo.service``. The runtime drop-in
       clears it.
   * - ``/etc/shirudo/map-export.env``
     - ``EnvironmentFile`` of ``shirudo-keepalive.service`` and
       ``shirudo-map-export.service``.
   * - ``/etc/shirudo/bpm/environment``
     - ``EnvironmentFile`` of ``shirudo-bpm-repo-update.service`` and
       ``shirudo-bpm-tree-sync.service``.

shirudo refuses a configuration file under ``/etc/shirudo`` or
``/var/lib/shirudo`` that is not a regular file, is owned by another
user than root or the caller, or is writable by group or others, and
the same for each directory its path leads through unless that
directory is root's and sticky. A symbolic link on the path must be
root's or the caller's, and the directory that holds it is checked like
the directories of its target. A ``shirudo.conf`` that sets
``tpm.owner_auth`` must also not be readable by group or others. The
``EnvironmentFile`` paths are read by systemd, not by shirudo.

Kernel and system interfaces
----------------------------

.. list-table::
   :header-rows: 1
   :widths: 42 58

   * - Path
     - Read for
   * - ``/dev/tpmrm0``
     - The TPM, through the default TCTI ``device:/dev/tpmrm0``.
   * - ``/dev/mapper/control``, ``/dev/loop-control``, ``/dev/loop*``,
       ``/dev/dm-*``
     - Creating and checking the dm-verity mappings of the images.
   * - ``/sys/kernel/security/lsm``, ``/proc/filesystems``
     - Pre-flight: BPF LSM active, bpffs supported.
   * - ``/proc/sys/kernel/random/boot_id``
     - The ``boot_id`` of eventlog records.
   * - ``/sys/kernel/security/tpm0/binary_bios_measurements``,
       ``/run/log/systemd/tpm2-measure.log``
     - The firmware and systemd event logs ``attest`` includes. ``init``
       appends the register's PCR 9 anchor to the systemd log.
   * - ``/sys/bus/event_source/devices/kprobe/type``,
       ``/sys/bus/event_source/devices/kprobe/format/retprobe``
     - Attaching kprobe and kretprobe programs.
   * - ``/sys/fs/cgroup``
     - Attaching ``cgroup_skb`` programs at the root cgroup.
   * - ``/sys/kernel/notes``, ``/boot/config-<release>``,
       ``/proc/config.gz``
     - Kernel build ID and configuration, matched by tree selectors.
   * - ``/etc/os-release``, ``/etc/machine-id``, ``/proc/meminfo``,
       ``/proc/uptime``
     - ``status --include-system``.
   * - ``/etc/initrd-release``
     - Whether ``init`` runs in the initrd.

Temporary files
---------------

The target commands create none. ``bpm info`` and ``bpm key`` keep a
downloaded package in a memory file, ``memfd:shirudo-bpm-package``, and
``upatch map --s3-uri`` its snapshot in ``memfd:shirudo-map-snapshot``:
a file of ``/tmp`` or of ``TMPDIR``, which root chooses, could be
created in a sealed directory bound there, with the label and content
from a registry.

Related
-------

- :doc:`/operate/maintain/backup-recovery`
- :doc:`/internals/seal`
- :doc:`/security/tamper-counters`
- :doc:`/reference/environment`
- :doc:`/reference/systemd-units`
