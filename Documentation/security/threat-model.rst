..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Threat model
============

This page states what shirudo protects, against whom, by which
mechanism, and where each mechanism stops. It describes the code in the
tree. Where the code and this page disagree, the code is right and the
page is a bug.

Purpose and how to read it
--------------------------

The page serves reviewers who judge whether the design holds, and
contributors who change a security-relevant path. Read it before you
change signature verification, an LSM hook, the TPM paths, the seal or
the artifact format. A change that keeps the shape of the code but
breaks a property below ships a false sense of safety to targets that
are hard to patch. :doc:`security-model` gives the short version for
operators.

Every entry has a stable ID that commits, issues and other pages cite:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - IDs
     - Meaning
   * - G1 to G8
     - Security goals: what shirudo sets out to provide.
   * - A1 to A15
     - Assumptions the goals depend on, and whether shirudo checks them.
   * - ADV-A to ADV-G
     - Adversaries.
   * - T1 to T15
     - Threats shirudo addresses, each with a fact box.
   * - R1 to R23
     - Residual risks: known and bounded limits of the mechanisms.
   * - U1 to U20
     - Threats to resolve: gaps in the code that are not closed yet.
   * - D1 to D10
     - Deferred mitigations that are in scope.

Each threat is explained in prose and then summarized in a fact box.
The fields of the box are:

- Adversary: who mounts the threat
- Enforced at: the BPF LSM programs that refuse it, by their section
  name in :src:`bpf/`, and after them the programs that refuse nothing
  and keep the state the refusals read
- Refusal: what the caller sees
- Counters: the tamper counters the refusal moves, described in
  :doc:`tamper-counters`
- Tests: the target tests under :src:`testing/functional/` that exercise
  the refusal
- Proofs: where a userspace check stands against the threat, the CBMC
  and Lean 4 proofs of it in
  :doc:`/contribute/testing/proof-coverage`; a proof holds for the code
  it reads, within its bounds, not for the kernel or the hooks
- Residual: the residual risks and threats to resolve that bound it

A claim on this page is one of three kinds, and the text says which. A
hook in the kernel enforces it, shirudo checks it in userspace, or an
operator detects it by verifying TPM evidence. The three are not
interchangeable. A userspace check runs in a process that root can
start, and detection needs a verifier who asks the right questions.

Security goals
--------------

.. list-table::
   :header-rows: 1
   :widths: 8 64 28

   * - ID
     - Goal
     - Threats
   * - G1
     - After ``init`` has attached the gates, every BPF program that a
       userspace process loads through ``bpf()`` is a signed loader the
       kernel verified against the sealed ``.bpf`` keyring, or a
       program such a loader loads.
     - T1, T4
   * - G2
     - The enforcement programs and the loaded upatches stay attached
       until shirudo removes them or the target reboots.
     - T2, T6
   * - G3
     - Only shirudo changes its writable state, its keyrings and its
       authorized processes.
     - T3, T11
   * - G4
     - Every change to the set of loaded upatches is measured in the
       TPM before or as it takes effect.
     - T5, T12, T14
   * - G5
     - A verifier tells a target in the expected state from one that is
       not by TPM-signed evidence, not by the target's own report.
     - T9
   * - G6
     - A refused attempt leaves a trace on the target.
     - T10
   * - G7
     - The artifacts, packages, trees and configs a target accepts are
       the ones the operator's keys signed.
     - T7, T8, T11
   * - G8
     - No process without runtime authority reads or drains the maps
       and pins of shirudo and its upatches.
     - T13

The goals hold only together with the assumptions below. None of them
says that a upatch is correct: shirudo establishes provenance, not
correctness.

.. _tm-assumptions:

Assumptions
-----------

Each assumption is a property of the deployment that the threats rely
on. The last column says whether shirudo checks it. Where it does not,
a deployment that breaks the assumption runs without an error and
without the protection.

.. list-table::
   :header-rows: 1
   :widths: 6 40 34 20

   * - ID
     - Assumption
     - Why it matters
     - Checked by shirudo
   * - A1
     - The kernel is trusted: the BPF verifier and JIT, the keyring and
       PKCS#7 code, dm-verity and the TPM driver behave as specified.
     - Every hook and every signature check runs in it.
     - No.
   * - A2
     - The BPF LSM is active. Another LSM ordered before ``bpf`` can
       refuse an operation first, and the BPF program then does not
       run.
     - All enforcement is BPF LSM programs.
     - Yes, the pre-flight check ``bpf_lsm_active`` reads
       ``/sys/kernel/security/lsm``. The order of the LSMs is not
       checked.
   * - A3
     - The kernel has the signed-loader ABI of the bpf-next tree shirudo
       targets, the ``tpm_command`` LSM hook, xattr kfuncs that return
       a ``security.bpf.`` label to an LSM program without the calling
       task's read permission, sleepable LSM programs on
       ``inode_mkdir``, ``inode_link``, ``inode_set_acl``,
       ``inode_remove_acl``, ``inode_file_setattr`` and
       ``inode_copy_up``, a ``dentry->d_parent`` the verifier trusts,
       and the ``mm_read_access`` LSM hook. Upstream has none of these,
       and :src:`testing/kernel/` carries them in the
       target kernel build.
     - T1 needs the ABI, T5 the hook, T3 the label read, the sleepable
       hooks, the trusted parent and the read-only mm access hook.
     - Partly. The pre-flight checks ``signed_loader_kernel_abi`` and
       ``kernel_lsm_hooks`` test the ABI and every LSM hook the
       programs attach to, ``tpm_command`` and ``mm_read_access``
       included, before ``init`` loads anything. Without the sleepable
       hooks and the trusted parent the ``seal`` object does not load;
       ``init`` fails either way. Without the
       label read, the seal falls back to its marks where a read fails
       for the caller (T3).
   * - A4
     - The kernel checks module signatures (``CONFIG_MODULE_SIG``), or
       loads no modules (``CONFIG_MODULES=n``).
     - An unsigned module is kernel code of root's choosing. A kernel
       that does not enforce signatures itself asks lockdown about one,
       and ``bpf2`` refuses it from ``init`` on through
       ``lsm/locked_down``, with the other ways root has to change or
       replace the running kernel that lockdown in integrity mode
       refuses, ``/dev/mem``, MSR writes, port I/O, PCI BAR access,
       debugfs writes and ACPI table overrides, and ``/proc/kcore``,
       which that mode leaves readable (``ModuleSignature`` and the
       other integrity counters, ``t6154``). The
       kernel's lockdown LSM is not needed for them, and where it runs
       it decides first. A kernel without ``CONFIG_MODULE_SIG`` asks
       nothing and loads any module.
     - Yes. The pre-flight check ``module_signatures`` refuses a
       kernel whose BTF shows modules (``__module_address``) without
       ``mod_verify_sig``, which only ``CONFIG_MODULE_SIG`` builds.
       Which keys the kernel trusts for modules is not checked.
       Lockdown in confidentiality mode would withhold
       ``bpf_probe_read_kernel()`` from shirudo's own programs and stop
       ``init``. This is a reading of the kernel source and is not
       tested.
   * - A5
     - 32-bit compatibility is off: ``CONFIG_COMPAT=n``, and on x86-64
       also ``CONFIG_IA32_EMULATION=n`` and ``CONFIG_X86_X32_ABI=n``.
     - The device-mapper and perf checks hook the native and the compat
       ioctl paths; no other 32-bit entry point is considered.
     - No.
   * - A6
     - The target boots with Secure Boot from a signed, measured UKI
       whose initrd carries shirudo, its bootstrap settings and the
       runtime root hash, and systemd measures the ``enter-initrd`` and
       ``leave-initrd`` phases into PCR 11.
     - ``init`` takes the runtime root hash from the initrd's
       ``/etc/shirudo/shirudo.conf``. The binding of the register to
       the initrd rests on the PCR 11 phase values.
     - No. shirudo checks neither Secure Boot nor where the initrd came
       from. ``init`` warns when PCR 11 holds no phase measurement.
   * - A7
     - Config signing keys are selected by the authenticated runtime
       bootstrap's repeated ``config.verification_key`` entries.
     - A config chooses repository certificates, vouched signers,
       revocations and export endpoints.
     - Yes. Before mapping a config, the target verifies its root
       signature against that exact certificate set. The kernel's
       dm-verity signature check is required as well. A built-in,
       secondary or platform key alone cannot authorize a config.
   * - A8
     - The TPM is reachable only through the kernel driver: no
       ``i2c-dev`` or ``spidev`` driver that root could bind to the
       TPM's bus, and no MMIO access to it (A4).
     - ``lsm/tpm_command`` sees only commands written to ``/dev/tpm0``
       and ``/dev/tpmrm0``.
     - No.
   * - A9
     - The boot resumes from no hibernation image: the command line has
       no ``resume=``, ``CONFIG_PM_STD_PARTITION`` is empty and the
       initrd names no resume device, or hibernation is off from boot
       (``CONFIG_HIBERNATION=n``, ``nohibernate`` or
       ``lockdown=integrity``).
     - A hibernation image is kernel memory on disk, and a resume runs
       in the initrd before ``init``, from an image root can write to
       swap. ``bpf2`` refuses hibernation once ``init`` runs, and the
       write of a ``HibernateLocation`` EFI variable, through which
       systemd's initrd resumes from a device the running system names
       (``HibernateLocation``). What the authenticated UKI names is
       left.
       The behavior of the register across hibernation is not analyzed
       here.
     - No.
   * - A10
     - No process writes to the block device under a mounted file
       system: ``CONFIG_BLK_DEV_WRITE_MOUNTED=n``.
     - The seal guards file operations. A write to the device under
       ``/var/lib/shirudo`` bypasses it.
     - No. See R19.
   * - A11
     - The kernel command line is authenticated as part of the UKI. It
       carries ``lsm=`` with ``bpf``, ``bpf.keyring_unsealed=1`` and
       ``dm_verity.keyring_unsealed=1``, no ``resume=`` (A9), and
       nothing that masks or skips ``shirudo-initrd.service``.
     - The command line decides whether the LSM runs, whether the
       keyrings accept shirudo's keys and whether ``init`` runs at all.
     - Partly. ``init`` refuses a ``.bpf`` keyring the kernel sealed
       empty at boot, which is what a boot without
       ``bpf.keyring_unsealed=1`` leaves.
   * - A12
     - The operator host is trusted: the signing key, clang/LLVM,
       libbpf, ``veritysetup`` and ``mkfs.ext4``.
     - They produce every signature and every image.
     - No.
   * - A13
     - The initrd is a dracut initrd with systemd 256 or newer and the
       phase measurement, and no other component restricts ``.bpf`` or
       ``.dm-verity`` before ``init``.
     - ``shirudo-initrd.service`` orders itself after ``tpm2.target``.
       A keyring sealed by someone else leaves no room for shirudo's
       keys.
     - Partly. ``init`` refuses a ``.bpf`` keyring that another task
       restricted or filled (``t6129``).
   * - A14
     - The runtime image holds no executable that exposes a generic
       primitive: a shell or interpreter, ``bpftool``, TPM tools,
       ``keyctl``, mount or device-mapper tools, a file editor.
     - Authority follows the exec, not the program. Every executable on
       the runtime image hands root shirudo's authority.
     - No.
   * - A15
     - The TPM is a correct TPM 2.0 with RSA-3072 and ECC P-256 support
       and an endorsement hierarchy without an authorization value.
     - The register, the NV writer, the session key and the attestation
       key live in it.
     - Partly. ``init`` requires ECC endorsement-key creation, salted
       session setup and RSA-3072 NV writer creation.

Assets
------

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Asset
     - Where it lives
     - What protects it
   * - Signing private key
     - The operator host, ``signing_key.pem`` beside ``cert.der``
     - Operator custody (A12). The signing code refuses a key file whose
       mode is not ``0600``. It never reaches a target.
   * - Enrolled BPF certificates
     - ``.bpf`` keyring
     - Sealed by ``init`` with a reject-all restriction;
       ``lsm/key_permission`` (T3).
   * - Config certificate
     - ``.dm-verity`` keyring, from the runtime image
     - Sealed by ``init``; ``lsm/key_permission`` (T3). The kernel also
       trusts the keyrings A7 names.
   * - Runtime image and its root hash
     - A dm-verity mapping mounted at ``/run/shirudo/runtime``; the root
       hash in the initrd's bootstrap settings and in the identity map
     - dm-verity, ``lsm.s/bdev_setintegrity`` and the mount hooks (T11);
       the boot chain (A6).
   * - Config images
     - Cache under ``/var/lib/shirudo/images``; the active one mounted
       at ``/run/shirudo/config``
     - The kernel's root-hash signature check, dm-verity, the seal on
       the cache (T11).
   * - Enforcement links and upatch links
     - Pins in the private bpffs at ``/run/shirudo/bpffs``
     - The bpffs inode and mount guards, the descriptor checks (T2).
   * - Identity map
     - ``shirudo_bpffs_sb``, pinned as ``identity``
     - Frozen by ``init`` and created with ``BPF_F_RDONLY_PROG``, so
       neither userspace nor a BPF program can write it; opened only by
       tasks with runtime authority (T13). It holds the keyring
       serials, the runtime root, the EK name, the NV writer seed and
       public key, and the NV index.
   * - Task marks
     - ``shirudo_tasks`` task storage, pinned as ``task_authority``
     - Frozen against ``bpf()`` writes; only the seal's programs set a
       mark (T3).
   * - Task policy bits
     - ``shirudo_task_policy`` task storage, pinned as ``task_policy``
     - Frozen against userspace writes; exec hooks OR protected inode
       values and commit only after a successful exec.
   * - Socket policy bits
     - ``shirudo_sock_policy`` socket storage, pinned as ``socket_policy``
     - Frozen against userspace writes; socket creation snapshots task
       bits and accepted sockets inherit the listener's value.
   * - Device records and expected roots
     - ``shirudo_devices`` (frozen) and ``shirudo_roots`` (not frozen,
       written by authorized tasks for their own config mapping)
     - The descriptor checks (T13); ``lsm.s/bdev_setintegrity`` (T11).
   * - Tamper counters
     - ``shirudo_tamper``, pinned as ``tamper``
     - Frozen; only the hooks add to it (T10).
   * - Integrity counters
     - ``shirudo_integrity``, pinned as ``integrity``
     - Frozen; only the hooks add to it (T6, T10).
   * - Payload binding of a pin
     - The ``security.bpf.shirudo.payload`` xattr on each upatch pin
       directory
     - ``lsm/inode_setxattr`` and ``lsm/inode_removexattr`` in the
       private bpffs (T4).
   * - Measurement register
     - TPM NV index ``0x01818E00``, cleared at TPM reset
     - Its write policy and ``lsm/tpm_command`` (T5).
   * - NV writer
     - An RSA-3072 owner-hierarchy primary, recreated from the seed in
       the identity map
     - The private key never leaves the TPM; the seed is not secret
       (T5).
   * - Attestation key
     - An ECDSA P-256 endorsement-hierarchy primary; its name pinned
       by the operator after enrollment
     - The TPM; the verifier's pin of its name (T9).
   * - Eventlog
     - ``/var/lib/shirudo/eventlog``; the initrd's record at
       ``/run/shirudo/eventlog.pending`` until adoption
     - The seal (T3) and replay against the register (T5).
   * - Writable state
     - ``/var/lib/shirudo``: archived upatches, keys, package and tree
       state, the config selection journal
     - The seal (T3). Across reboots only signatures and the register
       (R19).
   * - TPM owner password
     - ``tpm.owner_auth`` in the runtime image's ``shirudo.conf``
     - Nothing on the target: root reads it (R20).
   * - Registry and collector credentials
     - The environment of the bpm and export units, Docker and registry
       auth files, ``/etc/shirudo/map-export.env``
     - File permissions only; root reads them (U3).
   * - Host EnvironmentFiles
     - ``/etc/shirudo/bpm/environment``,
       ``/etc/shirudo/map-export.env``, ``/etc/shirudo/init.env``
     - Nothing: root writes them, and the processes that read them hold
       runtime authority (U3).
   * - Repository certificates
     - The signed config image
     - The config signature (T11).
   * - Status, reports and telemetry
     - The target's output and the collector
     - Nothing for reports and map snapshots. A keepalive's body is quoted
       by the TPM's attestation key, which shows it unchanged on the way
       but not that the key is a TPM's. All of them are the target's own
       account (R17).

.. _tm-trust-boundaries:

Trust boundaries
----------------

Figure 1 shows the parties and where trust ends.

.. figure:: /images/security-trust-boundaries.svg
   :alt: The operator host and the verifier on the left, the untrusted
         network with the registry and the collector in the middle, and
         the target on the right with its TCB of runtime tasks, kernel
         and TPM below the untrusted root processes and the sealed
         state. The evidence box splits the TPM-signed quote and NV
         certification from the target's own account.

   Figure 1. Trust boundaries and the evidence boundary.

The target TCB is the kernel with its configuration and command line
(A1, A4, A11) and the kernel project patches (A3); the firmware, boot loader
and UKI (A6); the TPM (A15); the initrd and every unit it runs before
``shirudo-initrd.service`` completes; and the runtime image. The
runtime image holds the shirudo binary with its two embedded BPF
objects, ``bpf2`` and ``seal``, the libraries it links (OpenSSL,
libcurl, tpm2-tss, libbpf, libelf, zlib, zstd, LuaJIT, the C library),
every other executable on the image (A14), the certificates
and the bootstrap settings. The memory of every task with runtime
authority is in the TCB too, the Lua decoders it runs included.

Every other process on the target, root with every capability among
them, is outside the TCB and constrained by it. Root is not trusted
because it is root. A task gains authority only by a successful exec of
a file on the runtime image (T3).

The operator TCB is the operator host, the signing key, clang/LLVM,
libbpf, ``veritysetup`` and ``mkfs.ext4`` (A12). The verifier is a
party of its own: it trusts the TPM's signatures and the values it
pinned, and nothing the target says about itself.

Outside both are the OCI registries, the network, the collectors, their
TLS certificates, and whatever remote access an administrator uses. A
registry can withhold and replay signed content. It cannot forge a
upatch, because the kernel verifies every loader (T1). What a registry
can do to indexes, tree publications and the transport is described in
T7 and U3 to U4.

The evidence boundary runs through the attestation document. Only two
parts of what ``shirudo attest`` produces are authenticated: the
``TPM2_Quote`` over the selected PCRs and the ``TPM2_NV_Certify`` of the
register, both signed by the attestation key over the verifier's nonce.
Everything else in the document is the target's own account: the
eventlog records, the config history, the fields of the init record
(``bound_in``, ``ts``, ``boot_id``, the certificate list and the set),
and the logs. A record proves something only through what folds into
the certified register value, into the certified index name or into a
quoted PCR. A check that depends on which records are present, such as
one init record per TPM reset, holds only for a document the target did
not trim. A check on a field no digest covers, such as
``--require-initrd`` on ``bound_in``, holds only for an honest target.

.. _tm-adversaries:

Adversaries
-----------

ADV-A, unprivileged local code
   Constrained by the kernel. shirudo adds nothing it needs, but every
   caller reaches ``lsm/bpf`` before the kernel checks capabilities, so
   unprivileged code can move the ``bpf()`` tamper counters (T10). Where
   an installation left a file or a directory of shirudo's to another
   user, the commands refuse the file (T3).

ADV-B, root on the target without the signing key
   The main adversary: a compromised administrator account, a container
   escape, a persistence implant. It issues any system call, writes any
   file the kernel lets root write, ptraces whatever the kernel allows, loads
   signed modules and runs any binary, the runtime image's included.
   shirudo must keep it from loading BPF, from detaching or replacing
   shirudo's BPF, from changing shirudo's state unnoticed, and from
   making a tampered target look healthy to a verifier.

ADV-C, root with mount-namespace and device control
   A refinement of ADV-B that uses private mount namespaces, bind
   mounts over shirudo's paths, overlays, substitute device nodes and
   ``/proc`` substitution to show a shirudo command a different world.
   T3, T11 and T14 address parts of it. R22 and U9 are the parts
   that remain.

ADV-D, network and registry
   Towards the target: observes, drops, delays and replays traffic, and
   serves any content a registry holds, old signed content included
   (T7, R8). Towards the operator: it serves what ``bpm tree append``
   and ``bpm config update`` build on, which the operator pins by
   ``--tree-id`` and ``--base-digest``.

ADV-E, malicious collector
   Receives keepalives and map snapshots. It can refuse or delay them
   and put a short error message into the target's log. It cannot
   change enforcement or state. A map snapshot it receives is
   unauthenticated; a keepalive it changes no longer matches its quote,
   but it can replay an old one to a backend that does not order them
   by the quote's clock (R17).

ADV-F, holder of a compromised or revoked signing key
   Its blast radius: every target whose ``.bpf`` keyring holds the key
   loads any loader it signed, until a config that revokes the key is
   activated there (R13). It unloads any upatch whose payload digest it
   knows (R1). Its loaders run ``bpf()`` calls from kernel context,
   which both gates admit, so it can open shirudo's maps and attach
   programs that write them: the maps are frozen against ``bpf()``
   writes, not against programs. A upatch does what its author wrote,
   disabling enforcement included. Keys it vouched for stay admitted
   where a config lists them (U13). Tree publications require a
   non-revoked member of the active config's BPF signer set.
   A key that signs configs (A7) chooses repositories, vouched signers
   and revocations.

ADV-G, physical access and TPM hardware
   Out of scope: bus interposers, TPM fault injection, cold boot, and
   offline changes to the disk beyond what R19 states.

Threats addressed
-----------------

.. _tm-t1:

T1 Loading unsigned BPF
~~~~~~~~~~~~~~~~~~~~~~~

Root's most direct move is to load a BPF program of its own: a kprobe,
an LSM program that allows what shirudo refuses, a program that writes
kernel data. The kernel would allow it, since root holds ``CAP_BPF`` and
``CAP_SYS_ADMIN``. Capabilities cannot tell root from shirudo, so the
gate rests on what root does not hold: the operator's signing key.

``lsm/bpf`` runs at the entry of every ``bpf()`` call, before the kernel
acts on the attributes or checks capabilities. For ``BPF_PROG_LOAD`` from
userspace it admits only a ``BPF_PROG_TYPE_SYSCALL`` program that
carries a signature (``LoadNotLoader`` and ``LoadUnsigned`` otherwise).
The kernel then verifies that signature in
``bpf_prog_verify_signature()``, over the loader's instructions and its
frozen metadata map, against the keyring that ``attr.keyring_id``
names. Booted with ``bpf.keyring_unsealed=1``, the kernel refuses a
caller-supplied user keyring with ``EPERM``.

``lsm/bpf_prog_load`` runs after that verification. It admits a
userspace load only when the kernel recorded a verified signature
against a keyring of the BPF kind, which is the ``.bpf`` keyring
``init`` enrolled and sealed (``LoadUnverified`` and ``LoadKeyringKind``
otherwise). A signature that verifies against the built-in, secondary
or platform keyring fails here. The hook also compares the keyring
serial with the one ``init`` froze (``LoadKeyring``), but the kernel
records serial 0 for the ``.bpf`` keyring and the hook skips the
comparison for 0, so on the target kernel the kind check is what pins
the keyring.

Root cannot assemble a validly signed loader outside shirudo either. A
loader needs its metadata map, and ``BPF_MAP_CREATE`` needs runtime
authority (``MapCreate``), as do filling and freezing the map
(``MapWrite``) and the routes to an existing one (T13).
The programs a verified loader loads run in kernel context, and both
hooks admit calls whose ``kernel`` argument is set.

A modified loader, one signed by a foreign key, or one whose certificate
the keyring does not hold fails in the kernel's signature check, before
``lsm/bpf_prog_load``, with the kernel's own error such as ``ENOKEY`` or
``EKEYREJECTED``. Those refusals move no counter.

The gates cover ``bpf()`` from userspace. In-kernel BPF users, classic
BPF and programs loaded before ``init`` are outside them (R18, R7), and
any loader the key ever signed passes (R16).

.. rst-class:: facts

:Adversary: ADV-B, root on the target without the signing key
:Enforced at: ``lsm/bpf``, ``lsm/bpf_prog_load``
:Refusal: ``EACCES`` from ``bpf()``; the kernel's signature errors, such
   as ``ENOKEY``, ``EKEYREJECTED``, or ``EPERM`` for a caller-supplied
   keyring
:Counters: ``LoadNotLoader``, ``LoadUnsigned``, ``LoadUnverified``,
   ``LoadKeyringKind``, ``LoadKeyring``, ``MapCreate``, ``MapWrite``
:Tests: ``t6102``, ``t6103``, ``t6104``, ``t6107``, ``t6108``, ``t6138``
:Residual: R7, R16, R18

.. _tm-t2:

T2 Detaching or replacing enforcement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A BPF program stays attached while something references its link: a
pin in a bpffs or an open descriptor. shirudo's commands exit after each
operation, so the pins in the private bpffs at ``/run/shirudo/bpffs`` are
the only lasting references to the enforcement links and the upatch
links. After a refused load, root's next move is to drop those
references, or to take one of its own that outlives them.

``lsm/bpf`` refuses to every userspace caller, shirudo included, the
commands that detach or replace a link or a program:
``BPF_LINK_DETACH``, ``BPF_LINK_UPDATE``, ``BPF_PROG_ATTACH``,
``BPF_PROG_DETACH``, ``BPF_BTF_LOAD``, the map deletions, and every
command it does not classify, including commands a newer kernel adds
(``BpfCommand``). It leaves ``BPF_LINK_CREATE``,
``BPF_RAW_TRACEPOINT_OPEN`` and ``BPF_OBJ_PIN`` to tasks with runtime
authority (``ProgAttach``, ``ObjPin``). Root therefore cannot attach a
vetted program at a site of its choosing, or pin an object into the
private bpffs.

A link descriptor keeps the link attached after shirudo removes the pin
for an unload, a revocation or the undo of a refused load, and no LSM
hook sees a link descriptor being handed out. ``lsm/bpf`` therefore
refuses ``BPF_OBJ_GET``, ``BPF_MAP_GET_FD_BY_ID`` and
``BPF_LINK_GET_FD_BY_ID`` to tasks without runtime authority, and
``lsm/file_open`` in the ``bpf2`` object refuses them the opening of any
non-directory inode in the private bpffs (``ObjGet``). Directories stay
listable. ``BPF_PROG_GET_FD_BY_ID`` and ``BPF_BTF_GET_FD_BY_ID`` stay
open for other program types. ``lsm/bpf_prog`` refuses an XDP descriptor
to a task without runtime authority (``ObjGet``), including acquisition by
ID, because netlink accepts it outside the ``bpf()`` attach guard. Other
shipped types attach nowhere without the commands above or the ioctl
below (R18).

The one attach that does not pass through ``bpf()`` is
``PERF_EVENT_IOC_SET_BPF``, which binds a program reached by id to a
perf event of the caller's. ``lsm/file_ioctl`` and
``lsm/file_ioctl_compat`` keep that ioctl number to tasks with runtime
authority (``PerfAttach``).

In the private bpffs, unlink, rename, mkdir, symlink, hard link, rmdir
and xattr changes need runtime authority (``PinUnlink``, ``PinRename``,
``PinEntry``, ``PinXattr``; rmdir is refused without a counter). The
VFS removes a rename's victim without asking ``inode_unlink``, so the
rename hook checks both directories. A symbolic link in place of a pin
directory would send the next load's pins into a bpffs of root's, and a
hard link to a pin would keep a link alive past its unlink.

The pins live as long as the bpffs superblock, which goes with its last
mount. ``lsm/sb_umount``, ``lsm/move_mount``, ``lsm/sb_mount`` and
``lsm/sb_remount`` refuse every caller, shirudo included, an unmount, a
move, a mount over or a remount of the private bpffs (``BpffsUmount``,
``BpffsMount``). Figure 2 shows the two ways an operation on a mount far
from the bpffs takes it along.

.. figure:: /images/security-bpffs-mounts.svg
   :alt: Three mount namespaces. In init's, the root, /run, the
         /run/shirudo tmpfs and the recorded bpffs nest in that order;
         unmounting the bpffs is refused with BpffsUmount, and
         unmounting /run, whose subtree holds it, with BpffsUmountAbove.
         In a peer namespace whose root is a peer of init's, unmounting
         its copy of /run propagates to init's /run and is refused by
         lsm/sb_umount with BpffsUmountAbove. In a namespace without
         /run mounted, /run is the bare directory, the same dentry init's
         /run is mounted on, and an rmdir of it would detach the mounts
         on it everywhere; lsm/inode_rmdir refuses it with
         BpffsUmountAbove.

   Figure 2. How an unmount or a removal away from the private bpffs
   reaches it.

The kernel asks ``sb_umount`` only about the mount it was given, but an
unmount takes that mount's subtree with it, and propagation repeats it
on the copies at the same mountpoint on the peers and slaves of its
parent. The hook therefore walks what the unmount would take: the
subtree, and for each mount in it those copies, from the bpffs mount
``init`` recorded, and refuses an unmount that reaches it
(``BpffsUmountAbove``). The walk runs without the namespace lock,
within fixed bounds of 1024 mounts, 32 levels and 4 masters, and
refuses a tree it cannot finish.

Removing a dentry detaches what is mounted on it in every namespace, and
renaming it moves those mounts, both without ``sb_umount``: from a
namespace where ``/run`` is not mounted, an ``rmdir`` of the directory
init's ``/run`` covers would take the bpffs along. ``lsm/inode_rmdir``,
``lsm/inode_unlink`` and ``lsm/inode_rename`` refuse a task without
authority the removal or rename of the mount point of the recorded
bpffs mount or of any mount above it (``BpffsUmountAbove``, ``t6155``).

The tmpfs at ``/run/shirudo`` gets the same treatment without counters:
no caller unmounts, moves or remounts it, and only authorized tasks
mount onto it.

Root also controls part of the site a load attaches at, since root
runs ``shirudo upatch load``. A ``cgroup_skb`` program attaches at the
root of the caller's cgroup namespace, a ``netfilter`` program in the
caller's network namespace, and a kprobe through the PMU that sysfs
names. The load compares the link the kernel reports with the signed
attach metadata before it pins the link, and refuses
``attach_scope_mismatch``.
XDP discovery requires the initial network namespace, classifies devices
from kernel interfaces and expands the signed device-class mask there.
It selects one endpoint per veth pair and checks device class, peer scope
and the returned link's ifindex around attachment.

.. rst-class:: facts

:Adversary: ADV-B, root on the target without the signing key
:Enforced at: ``lsm/bpf``, ``lsm/bpf_prog``, ``lsm/file_open``, ``lsm/file_ioctl``,
   ``lsm/file_ioctl_compat``, ``lsm/inode_unlink``,
   ``lsm/inode_rename``, ``lsm/inode_mkdir``, ``lsm/inode_symlink``,
   ``lsm/inode_link``, ``lsm/inode_rmdir``, ``lsm/inode_setxattr``,
   ``lsm/inode_removexattr``, ``lsm/sb_umount``, ``lsm/move_mount``,
   ``lsm/sb_mount``, ``lsm/sb_remount``
:Refusal: ``EACCES`` from ``bpf()``, from opening a pin and from the
   perf ioctl; ``EPERM`` from the inode and mount guards;
   ``attach_scope_mismatch`` from ``shirudo upatch load``
:Counters: ``BpfCommand``, ``ProgAttach``, ``ObjPin``, ``ObjGet``,
   ``PerfAttach``, ``PinUnlink``, ``PinRename``, ``PinEntry``,
   ``PinXattr``, ``BpffsUmount``, ``BpffsUmountAbove``, ``BpffsMount``
:Tests: ``t6105``, ``t6106``, ``t6107``, ``t6108``, ``t6109``,
   ``t6116``, ``t6119``, ``t6120``, ``t6121``, ``t6138``, ``t6155``,
   ``t3111``
:Residual: R1, R2, R3, U17

.. _tm-t3:

T3 Tampering with shirudo's files and process
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

shirudo keeps its archive of loaded upatches, the eventlog, the keys,
the package and tree state, the config selection journal and the image
cache under ``/var/lib/shirudo``. Root owns that file system, and
neither permissions nor ownership stop root. A changed archive would be
restored at the next boot, a truncated eventlog would make the register
unexplainable, and a planted file would be taken for shirudo's own.

The seal (:src:`bpf/seal.c`) marks shirudo's inodes with the extended
attribute ``security.bpf.shirudo`` and checks every operation on a
marked inode against the caller's authority. ``init``
labels the existing tree on the run that brings enforcement up, before
the seal attaches. On every later run a state root without the label is
refused, since it is a tree bound over the path rather than the one
``init`` sealed (``t6123``). For a labeled inode, a write open, an
unlink or the removal of an empty directory, either end of a rename, a
setattr (truncate, chmod, chown, utimes), a change of its inode flags
with ``chattr``, an xattr change and a change of its POSIX ACL need
runtime authority (``SealWrite``, ``SealUnlink``, ``SealRename``,
``SealSetattr``, ``SealXattr``); every one of those hooks reads the
label. Only an authorized task sets or removes the exact seal label or
changes the policy label on any inode (``SealLabel``). XFS also changes
attributes by file handle, ``XFS_IOC_ATTRMULTI_BY_HANDLE``, through no
xattr hook, so ``lsm/file_ioctl`` refuses that ioctl on XFS to tasks
without authority (``XattrHandle``, ``t6153``).

A rename of a directory above the state root, ``/var/lib`` say, would
move the sealed tree aside for the next boot's bootstrap run of
``init`` to label whatever root then puts at the path. That run marks
the directories above the state root on its file system with
``security.bpf.shirudo.ancestor``, and the seal refuses a task without
authority a rename of a marked directory or over it (``SealRename``)
and the setting or removal of the mark (``SealLabel``) (``t6150``).
What the next boot mounts at the path stays root's choice (R19).

The label is a public constant, the same on every build. It marks a
target and never grants authority: a file system root mounts can carry
it, and a binary that carries it gains nothing. What a label read decides is the
table of :ref:`seal-label-verdict`: no label, or no security extended
attributes, lets an operation through, a permission error does so only
where neither the inode nor the directory the operation changes carries
a mark, and every other result requires authority (``t6111``). With
the carried xattr patch (A3) the permission errors do not occur;
upstream, root brings them about with an idmapped bind mount or an ACL
and a file system uid that cannot read. The seal marks every inode
it labels at creation, every file shirudo opens, every file anyone
opens for writing, every directory anyone opens and the directory of
every new entry, from the label the entry hook reads; the marks are a
cache that only ``lsm/inode_init_security``, which has no dentry to
read from, decides by. The labels
themselves are refused to such a caller whatever the read said: root
takes a file system uid that cannot read the inode with ``setfsuid()``
and keeps the ``CAP_SYS_ADMIN`` that a ``security.*`` xattr change
needs, so the read fails where the removal would pass (``t6111``).

Executables may carry ``security.bpf.shirudo.policy``, an 8-byte
target-native ``__u64`` bitset. During exec, the seal ORs the value from
the original file and each interpreter into ``shirudo_task_policy``. Only
``ENODATA`` or ``EOPNOTSUPP`` means no policy; malformed or unreadable
values refuse exec.
The candidate starts with the task's committed bits, so successful exec
accumulates policy bits and an unlabeled exec preserves the existing
value. Failed exec preserves the previous value, and children inherit
the committed value. The xattr remains on the inode, and only a task
with runtime authority may set, update or remove it (``SealLabel``).

A signed upatch with an ``SHPL`` path-to-policy section opts into the
shared task and socket policy maps. The builder requires compatible map
declarations, and the target supplies both pinned map FDs to the
generated loader. After the load, shirudo ORs each entry's bit into the
policy xattr of its path. A path whose last component is a pattern
labels the regular files of its directory that match, and no symbolic
link among them: root, who owns the directory, could otherwise point a
matching name at a file the signed pattern does not name. It reads the
artifact once and takes the
entries from the copy it handed to the kernel, not from the file again,
so a task that writes the artifact during the load cannot have shirudo
set a label the signature does not cover. The upatch's signed BPF
programs can inspect task and socket policy values at any supported LSM
hook. Authors are expected to read these values; the verifier does not
prevent signed programs from changing them. upatches without ``SHPL``
receive no binding to these maps.

A labeled directory takes new entries, by create, mkdir, symlink,
mknod, hard link or rename, only from authorized tasks (``SealEntry``):
each entry hook reads the directory's label from the new entry's parent
dentry, which the carried patches 0022 and 0023 (A3) make possible by
letting a sleepable program attach to ``inode_mkdir`` and ``inode_link``
and by trusting ``dentry->d_parent``, and refreshes the directory's
mark on the way, from which ``lsm/inode_init_security`` gives the new
inode its label inside the transaction that creates it. Evicting the
inode cache therefore opens nothing (``t6118``, ``t6144``). A labeled
inode is hard-linked nowhere by a task without authority, so its label
cannot be kept alive beside the state it left. An overlay copy-up of a
labeled inode is refused to every caller, shirudo included
(``SealCopyUp``), so a write through an overlay root mounts over sealed
state fails instead of landing in root's upper directory.

shirudo opens sealed state without following symbolic links and takes
no entry without the label for its own: ``init`` ignores such an entry
rather than labeling, following or restoring it. A path that root
names for shirudo to write, a report, an export, evidence or a
download, must be a regular file without the label that is not reached
through a symbolic link and not created under a labeled directory. When
root makes the write fail, shirudo removes the file through the
directory it opened it in, and only while the name still holds the
inode it wrote, never by resolving the path again, where a directory
root swapped for a link would lead it to sealed state (``t6007``).
``genkey`` refuses to run where shirudo enforces, so that no target holds
a private key and root cannot have shirudo write a key pair into sealed
state (``t6114``). The
contents of a config image are read from the descriptor of its verified
root with ``openat2(2)`` and ``RESOLVE_BENEATH``, or one component at a
time without following links, never through a ``/proc/<pid>/fd`` path
that root could mount over. shirudo opens that descriptor once and
checks it where it opened it, for the image's device and the root inode
of its file system: a path checked and then opened is root's to swap in
between, and a directory of the image bound in place of its mount has
the image's device but leads every relative path elsewhere (``t6149``).

The ``.bpf`` and ``.dm-verity`` keyrings are sealed with
``KEYCTL_RESTRICT_KEYRING`` and no restriction type, so the kernel
rejects every further link. ``init`` refuses a keyring that holds
anything besides the trusted certificates, a nested keyring or a key it
cannot describe included, and one that another task restricted.
``lsm/key_permission`` refuses write, setattr, unlink and search
through an unpossessed reference, on both keyrings, the config key and
the enrolled keys, to tasks without authority (``KeyringWrite``). That
covers clear, unlink, revoke, invalidate, a permission change and a
timeout. Viewing, reading and linking a key elsewhere stay open, and
the kernel's own signature search uses a possessed reference.

Authority is a mark in task storage. A task becomes authorized only by
a successful exec of a file that sits directly on the runtime image
``init`` recorded, not through an overlay, while the task is neither
traced nor under a seccomp filter and shares its root and working
directory with no other process; the initrd's ``init`` process receives
a bootstrap mark through a pidfd before the gates attach. Figure 1 in
:ref:`seal-task-marks` shows how a task gets, keeps and loses the mark.

A task that dumps core loses its authority (``SealCoreDump``). The
kernel's dump code runs as the task and unlinks and creates the file
``kernel.core_pattern`` names, root's choice. An exec can fail after
its mark was committed, when root gives it a stack too small for its
arguments, and the task then dumps core before shirudo has run: a pin
or a sealed file at that path was the dump's to remove (``t6145``).

A task whose memory a uprobe reaches loses its authority as well
(``SealUprobe``, ``t6146``). Root sets uprobes on the runtime binary
through tracefs or perf, where no hook sees them, and a probe's
reference counter has the kernel add to a value in the task's writable
data at every exec: a variable shirudo reads before ``main()`` runs, a
descriptor it takes for closed among them, changed under it. What a
probe reads, a command's arguments and memory, is what root learns by
running the command (R2).

An authorized process is protected against being taken over:

- ``lsm/ptrace_access_check`` refuses every ptrace mode against a marked
  task. It counts an attach-mode access, which covers attach,
  ``/proc/<pid>/mem``, ``pidfd_getfd(2)`` and ``process_vm_readv(2)``
  (``SealPtrace``), and refuses a read-mode one, which covers
  ``/proc/<pid>/exe``, ``environ``, ``maps`` and the ``fd`` links,
  without a counter. ``lsm/mm_read_access`` refuses the read-only
  access ``mm_access()`` would otherwise grant ``CAP_PERFMON`` past that
  refusal (carried patch 0024, A3).
- ``lsm/perf_event_alloc`` refuses a perf event bound to a marked task
  (``SealPerf``). Events on all tasks of a CPU, and events opened on a
  task before the exec that marks it, are not checked (D9).
- ``lsm/task_kill`` counts a signal to a marked task from a task
  without authority (``SealSignal``) and lets it through: root can stop
  a command (R2, U17), and the count shows that it did. A command resets
  its file size and CPU time limits and disarms its interval timers
  when it starts, since exec keeps them and the kernel would signal it
  by them, and ``lsm/task_setrlimit`` refuses another task a change of
  its limits (``SealRlimit``, ``t6156``).
- The exec of a runtime file by a traced task is refused
  (``ExecTraced``), and so is one by a task that shares its root and
  working directory with another process (``ExecShared``), which could
  ``chroot`` or ``chdir`` the command while it runs, and one under a
  seccomp filter, without a counter.
- ``lsm/bprm_check_security`` in the ``bpf2`` object runs every
  runtime executable in secure-exec mode, so the C library ignores the
  loader variables, and shirudo itself is static.
- ``lsm/task_prctl`` refuses ``PR_SET_MM_EXE_FILE`` and
  ``PR_SET_MM_MAP`` to tasks without authority (``ExeIdentity``). The
  mark does not depend on the executable link in any case.
- ``lsm/mmap_file`` and ``lsm/file_mprotect`` refuse an authorized task,
  other than the bootstrap task, an executable mapping that is writable
  or not backed by the runtime image.
- At start, shirudo makes itself non-dumpable, sets no-new-privileges,
  disables core dumps, loads no OpenSSL configuration file, resolves
  host names without NSS modules and locks its memory, and refuses to
  run when the lock fails.

The kernel's permissions keep every other user out of these files, and
out of the settings, package sources and certificates under
``/etc/shirudo``. An installation can still get them wrong: a directory
handed to a group, a certificate copied in under another owner, a link
left by a user. A command therefore takes a file under ``/etc/shirudo``
or ``/var/lib/shirudo`` that steers what it trusts only when it is a
regular file of root's or of the user running the command that nobody
else can write, reached through directories and symbolic links that are
theirs too; a file that holds the TPM owner's authorization must not be
readable by anyone else either. The command follows the path one name
at a time through descriptors, so that what it checks is what led to
the file it opened and not what the name leads to a moment later, and
it opens and checks again a file renamed over in between. Anything else
is refused with ``EPERM``, or ``ESTALE`` for a name that keeps
changing. The check holds another user, not root, who passes it and is
held by the seal and the config image instead. It applies to a path as
the command was given it: one that the environment or an option points
elsewhere is the caller's to vouch for (U3).

.. note::

   Every ptrace mode against a shirudo task is refused, but only an
   attach-mode access is counted. A read-mode probe, such as journald
   reading ``/proc/<pid>/exe`` for a log line or ``ps`` reading
   ``/proc/<pid>/stat``, or a read of ``environ``, ``maps`` or the
   ``fd`` links, is refused silently: the caller gets ``EACCES`` and may
   log it, but ``SealPtrace`` and the keepalive do not move. Honest
   system services make read-mode checks against every process that
   logs, so counting them would make a healthy node read as tampered.

.. rst-class:: facts

:Adversary: ADV-B and ADV-C; ADV-A where a file's permissions went wrong
:Enforced at: ``lsm.s/file_open``, ``lsm.s/inode_unlink``,
   ``lsm.s/inode_rmdir``, ``lsm.s/inode_rename``, ``lsm/file_ioctl``,
   ``lsm/file_ioctl_compat``,
   ``lsm.s/inode_setattr``, ``lsm.s/inode_setxattr``,
   ``lsm.s/inode_removexattr``, ``lsm.s/inode_set_acl``,
   ``lsm.s/inode_remove_acl``, ``lsm.s/inode_file_setattr``,
   ``lsm.s/inode_create``, ``lsm.s/inode_mkdir``,
   ``lsm.s/inode_symlink``, ``lsm.s/inode_mknod``, ``lsm.s/inode_link``,
   ``lsm/inode_init_security``, ``lsm.s/inode_copy_up``,
   ``lsm/key_permission``,
   ``lsm.s/bprm_check_security``, ``lsm.s/bprm_committed_creds``,
   ``lsm/task_alloc``, ``lsm/bprm_check_security``,
   ``lsm/ptrace_access_check``, ``lsm/mm_read_access``,
   ``lsm/perf_event_alloc``, ``lsm/task_setrlimit``,
   ``lsm/task_prctl``, ``lsm/mmap_file``, ``lsm/file_mprotect``; in
   support, ``lsm.s/bprm_creds_for_exec`` and ``lsm/socket_post_create``
   carry the policy bits, ``lsm.s/inode_post_setxattr`` and
   ``lsm.s/inode_post_removexattr`` refresh an inode's mark, and
   ``lsm/task_kill`` counts a signal it lets through
:Refusal: ``EACCES`` from the seal and the task hooks; ``EPERM`` from a
   copy-up, a traced exec in the ``bpf2`` hook, ``PR_SET_MM`` and
   ``prlimit``;
   ``tampered`` or a foreign-entry warning from shirudo; ``EPERM`` or
   ``ESTALE`` for a file another user could change
:Counters: ``SealWrite``, ``SealUnlink``, ``SealRename``,
   ``SealSetattr``, ``SealXattr``, ``SealLabel``, ``SealEntry``,
   ``SealCopyUp``, ``KeyringWrite``, ``SealPtrace``, ``SealPerf``,
   ``SealSignal``, ``SealCoreDump``, ``SealUprobe``, ``SealRlimit``,
   ``ExecTraced``, ``ExecShared``, ``XattrHandle``,
   ``ExeIdentity``
:Tests: ``t6001``, ``t6006``, ``t6007``, ``t6110``, ``t6111``,
   ``t6112``, ``t6113``, ``t6114``, ``t6115``, ``t6118``, ``t6123``,
   ``t6124``, ``t6127``, ``t6129``, ``t6131``, ``t6133``, ``t6134``,
   ``t6135``, ``t6136``, ``t6137``, ``t6144``, ``t6145``, ``t6146``,
   ``t6149``, ``t6150``, ``t6152``, ``t6153``, ``t6156``, ``t7114``
:Residual: R2, R19, R22

T4 Substituting artifacts
~~~~~~~~~~~~~~~~~~~~~~~~~

A signed artifact is only as useful to root as the parts it can change.
If the name a upatch loads under, the sites it attaches at, or the
upatch an unload directive removes sat outside the signature, root
could aim a signed program elsewhere or turn one directive against
another upatch.

The signature covers the loader's instructions and the data in its
frozen metadata map, and the kernel refuses a modified loader. The
metadata map is exclusive to its loader through ``excl_prog_hash``, the
SHA-256 of the loader's instructions. The name, the attach metadata, and
for an unload directive the target name and the expected payload digest
ride in signed sections of that data. A load takes its attach sites
from nowhere else, and refuses an artifact whose attach metadata the
signature does not cover or whose header program and map counts, which
place each program's descriptor in the loader context, differ from the
signed ones (``parser_rejected``).

The signature covers the instructions and the data as one run of bytes,
and the container header that says where the instructions end is not
signed. Root could move that end: the kernel checks the same signature
over the same bytes, and the pin, the register and the evidence would
record the same payload digest for another loader over other data. The
signed bytes decide the end themselves: their last 16 are the trailer of
the signed sections, the section directory must end where that trailer
begins, and its offset and count then give the length of the data. A
header that divides the signed bytes elsewhere leaves an artifact
without signed sections, which a load refuses for its missing signed
name (``parser_rejected``) before the kernel sees a loader. Past
shirudo, root without runtime authority can neither create nor fill a
metadata map, and the signed bytes as instructions alone end in data no
instruction reaches, which the verifier refuses.

An unload directive is a signed loader of its own and goes through the
same ``BPF_PROG_LOAD``. Before it removes anything, shirudo compares the
payload digest recorded on the upatch's pin directory, in the xattr
``security.bpf.shirudo.payload`` that only authorized tasks can change
(``PinXattr``), with the directive's signed expected payload. It refuses
``payload_mismatch`` when they differ or when the xattr cannot be read.
With no pins, it removes the name's archive only when the archive's
bytes are the expected payload. A directive therefore removes the
upatch its signer made it for and no other.

The Lua decoders that map export runs with runtime authority ride in a
signed section too. Export reads them from the archived artifact only
when its bytes hash to the payload digest on the pin directory, so a
decoder runs only beside the maps of the payload it was signed with. No
test makes the two differ, which takes runtime authority.

.. rst-class:: facts

:Adversary: ADV-B, root on the target without the signing key
:Enforced at: ``lsm/bpf_prog_load``, ``lsm/inode_setxattr``,
   ``lsm/inode_removexattr``
:Refusal: the kernel's signature error for a modified loader;
   ``payload_mismatch`` and ``parser_rejected`` from ``shirudo upatch``
:Counters: ``PinXattr`` for a forged payload binding; none for a
   modified loader, which the kernel refuses first
:Tests: ``t2002``, ``t3104``, ``t6117``, ``t6138``
:Proofs: ``upatch-header``, ``upatch-signed-sections``,
   ``upatch-signed-name``, ``upatch-name``, ``upatch-prog-specs``,
   ``upatch-prog-uprobes``, ``upatch-uprobe-targets``,
   ``upatch-prog-kprobes``, ``upatch-decoders``,
   ``upatch-policy-labels``
:Residual: R1, R16

.. _tm-t5:

T5 Silent state change
~~~~~~~~~~~~~~~~~~~~~~

A target that loads or unloads upatches without a record cannot be told
apart from a healthy one. Every ``init``, load, unload, revocation and
tree operation therefore extends the measurement register with a
domain-separated SHA-256 event and appends the event to
``/var/lib/shirudo/eventlog``. A TPM 2.0 is mandatory and there is no
unmeasured mode. :doc:`/internals/measurement-register` describes the
register in detail.

The register is a TPM NV extend index, ``0x01818E00``, that the TPM
clears at every reset. Its write policy is a ``PolicyOR`` of two
branches. The written branch needs the index to be written. The init
branch needs it unwritten and PCRs 9 and 11 at the values the policy
was computed from. Both continue with a ``PolicySigned`` by the NV
writer over the session nonce and the hash of the exact
``TPM2_NV_Extend`` command, and with ``PolicyCommandCode`` for
``TPM2_NV_Extend``. ``init`` performs the first write from the initrd,
before ``leave-initrd`` moves PCR 11, and extends PCR 9 with the index
name right after it. An index recreated at runtime under the same
policy cannot be written, because PCR 11 has moved. One recreated under
a policy over the runtime PCR values has another name, which a verifier
that pins the binding values rejects (U9).

The NV writer is an RSA-3072 primary key in the owner hierarchy. Its
private key never leaves the TPM, but the seed it is recreated from is
not secret, so root can recreate the writer and have the TPM sign. A
signature alone does not change the register: the TPM must receive the
``TPM2_NV_Extend``. ``lsm/tpm_command``, the hook of A3, sees every
command written to ``/dev/tpm0`` or ``/dev/tpmrm0`` before the driver
queues it, and refuses an ``NV_Extend`` of shirudo's frozen index from a
task without authority, through inherited and nonblocking descriptors
too (``TpmExtend``). The same hook classifies every other command
(:doc:`/internals/measurement-register`, TPM command authority). Only shirudo may
mutate its register, extend or reset the config PCR, change the
hierarchies or send an unknown command. systemd's NvPCRs accept
extensions only, so no root process can delete and recreate one that its
PCR 9 anchor names. Every refusal counts as ``TpmWrite``. Other NV
indices, other PCRs and TPM signing stay open to everyone.

The order of the steps decides what a crash or a stopped process
leaves, and Figure 3 in :ref:`register-lock` draws it for a load, an
unload and a purge. A load whose archive copy or extension fails is
undone, pins and archive. An unload or a purge is measured before it
detaches, so an interruption leaves a register that claims more than
happened, never a detach it does not know. A load that root stops
between its pins and its extend, with ``SIGKILL`` say (counted as
``SealSignal``), leaves pins the register does not cover and the upatch
attached: ``shirudo status`` reports them (``UpatchesMeasured``, verdict
``tampered``), and the next upatch command, ``bpm``'s included, undoes
them before it acts and refuses when it cannot read the records or undo
them. The same pass removes the pins an unload stopped after its append
leaves, and an archive without a record of its load; ``init`` restores
only an archive whose load the eventlog records without a later unload
(``t6144``).

The undo takes only the records the register vouches for: it starts at
the init record that names the live index and the TPM's reset count,
derives every record's digest from its fields and folds them to the
value the TPM reports, and refuses ``tampered`` when they do not fold. A
boot ID that root binds over ``/proc``, or a pending record in a
``/run`` of root's making, which no reader takes since it carries no
seal label, therefore moves nothing (``t6147``). One lock, the root of
the private bpffs, orders every extend and append and covers the undo,
in every mount namespace, so the register and the log advance in one
order and the undo never takes a load in flight for a stopped one
(``t6128``). A failure or a stop between an extend
and its append leaves the register ahead of the log; shirudo reports
the desync, ``shirudo status`` reports a register its replay cannot
explain, and every later load and unload refuses until the next reboot.

``init`` binds one register per TPM reset. On a re-run with this boot's
record it reuses the register and adds no event; when the register it
recorded is gone or replaced it refuses ``tampered``. Which record
counts as this boot's depends on what the caller sees (U9). A load or
an unload refuses ``eventlog_full`` before it touches the TPM when the
log would exceed ``eventlog.max_bytes``, and ``init`` checks the limit
before it binds; each refuses as well when the settings that hold the
limit cannot be read. The ``tree_op`` and ``key_revoke`` events do not
check it (U6).
``upatch load`` and ``upatch unload`` given ``--expect-chain`` compare
it with the register before acting. The comparison is not atomic with
the extend and does not serialize concurrent commands, and package and
tree operations run without it.

.. rst-class:: facts

:Adversary: ADV-B, root on the target without the signing key
:Enforced at: ``lsm/tpm_command``
:Refusal: ``EACCES`` from ``write(2)`` on the TPM device; ``tampered``,
   ``tpm_error`` and ``eventlog_full`` from shirudo
:Counters: ``TpmExtend``, ``TpmWrite``
:Tests: ``t0057``, ``t4002``, ``t4003``, ``t4102``, ``t4103``, ``t6115``,
   ``t6122``, ``t6128``, ``t6143``, ``t6144``, ``t6147``
:Proofs: ``Shirudo.Chain``, ``Shirudo.Events``, ``Shirudo.Measured``,
   ``Shirudo.UpatchLoad``, ``chain-events``, ``measured-fold-model``,
   ``eventlog-records``, ``tpm-digest``
:Residual: R4, R12, R20, U6, U9

T6 Boot window
~~~~~~~~~~~~~~

Enforcement is BPF and does not survive a reboot. Until ``init`` has
attached the gates, nothing refuses anything.
``shirudo-initrd.service`` runs ``init`` in the initrd, after the root
file system is mounted at ``/sysroot`` and the ``enter-initrd`` phase is
measured, and before the switch to the root file system. There ``init``
binds ``/sysroot/var/lib/shirudo`` writable, enrolls the config
certificate in ``.dm-verity`` and seals it, enrolls the runtime
certificate and the vouched config signers in ``.bpf`` and seals it,
labels the state, attaches the guards, mounts the runtime image, restores the
archived upatches and binds the register with exactly one init event.
The pins and the identity map live under ``/run``, which systemd
carries across the switch. ``shirudo.service`` then runs ``init`` again
from the runtime image and adopts the initrd's eventlog record.
:doc:`/internals/boot-flow` follows the sequence step by step.

A kexec would open that window again without closing this boot. It
hands the machine to a kernel and an initrd of root's choosing with the
TPM as it is: PCRs 9 and 11 at this boot's values and the register with
this boot's history, so this boot's evidence would vouch for whatever
runs next. ``lsm/kernel_load_data`` and ``lsm/kernel_read_file`` refuse
every kexec image and initramfs to every task, shirudo included, by
either system call (``Kexec``).

The kernel that runs this boot has other ways in: ``/dev/mem``, MSRs,
port I/O, PCI resources, debugfs writes and ACPI table overrides change
it, an unsigned module joins it, and ``/proc/kcore`` reads it.
``lsm/locked_down`` refuses what lockdown in integrity mode refuses, an
unsigned module the kernel asks about included (A4), and
``/proc/kcore`` with it, to every task, whatever the command line says,
and counts each refusal on the integrity counter of its reason. A
kernel that does not ask about an unsigned module, one without
``CONFIG_MODULE_SIG``, fails the pre-flight check
``module_signatures``.
Hibernation is refused too, but a resume runs in the initrd before
``init``: ``lsm/file_open`` refuses the write of a ``HibernateLocation``
EFI variable, which would have the next boot's initrd resume from a
device root chose (``HibernateLocation``), and A9 keeps the UKI from
naming one. :doc:`integrity-counters` lists the counters.

.. rst-class:: facts

:Adversary: ADV-B, root on the target without the signing key
:Enforced at: ``lsm/kernel_load_data``, ``lsm/kernel_read_file``,
   ``lsm/locked_down``, ``lsm/file_open``
:Refusal: ``EPERM`` from ``kexec_load(2)`` and ``kexec_file_load(2)``,
   from each lockdown check and from the open of a
   ``HibernateLocation`` EFI variable for writing
:Counters: ``Kexec``; the integrity counters ``ModuleSignature``,
   ``DevMem``, ``EfiTest``, ``KexecSignature``, ``PciAccess``,
   ``IoPort``, ``Msr``, ``AcpiTables``, ``DeviceTree``, ``PcmciaCis``,
   ``Tiocsserial``, ``ModuleParameters``, ``Mmiotrace``, ``Debugfs``,
   ``XmonWrite``, ``BpfWriteUser``, ``DbgWriteKernel``,
   ``RtasErrorInjection``, ``XenUserActions``, ``Kcore``,
   ``HibernateLocation`` and ``Other``
:Tests: ``t4003``, ``t4101``, ``t6126``, ``t6154``, ``t6157``
:Residual: R6, R7, R12, U11, U16

.. _tm-t7:

T7 Delivery path
~~~~~~~~~~~~~~~~

Targets pull packages and trees from OCI registries that shirudo does
not trust. ``shirudo bpm repo update`` fetches a repository's index and
its detached CMS signature and verifies them against the repository
certificate in the signed config image. The sealed cache binds the index
to the source name, endpoint, index repository and SHA-256 of that
certificate. Indexed installs and upgrades check the binding against the
active source before selecting a package. A package installed from a
repository must match the digests in that index, and the loader in it
is a signed upatch the kernel verifies at load (T1).

``shirudo bpm tree sync`` fetches a signed tree publication and verifies
it against the active config's non-revoked BPF signer set. Every
member must also be present in the sealed ``.bpf`` keyring. A publication
carries a digest for each operation, is the one the target recorded or
has a higher generation, and names its parent, which the target
compares when the generation is exactly one higher. The target records
a publication when it accepts it, before it applies the first new
operation, so one it stopped in the middle of is not followed by an
older one. It refuses a publication whose operations up to its last
applied one are not the ones it processed, by the history root its
``outcomes`` record holds, and a segment that does not start from that
root at its base. It takes a publication only under the manifest that
``bpm tree append`` writes for its two layers, byte for byte, so that the
manifest digest it records and a successor names follows from the signed
layers: a registry that serves them under a manifest of its own, which
would leave a node with one digest refusing the other for good, is
refused before the node records anything. A node behind the segment the tag names walks back
through the sealed segments by digest, each signed and naming the one
before it, up to a limit of 65,536 operations, or 1,048,576 for a node
that has processed none, so a registry can neither splice another
history in nor keep a node walking without end. A delete applies
the signed unload directive whose name equals the operation's id. An
operation's ``fixes``, which the backend reads and the operation digest
does not cover, the target's parser skips: a malformed one cannot make
it refuse a publication.

The transport is TLS 1.3 only, with the hybrid groups
``X25519MLKEM768`` and ``SecP256r1MLKEM768`` and certificate
verification. ``tls.classical_hosts`` in the runtime image's bootstrap
settings opts exact host names into the classical groups ``X25519`` and
``secp256r1`` as well, and shirudo logs a warning when one is
negotiated.

A registry can still withhold or replay signed content (R8). The
environment of the bpm units selects parts of the transport (U3), index
and tree signatures accept algorithms other than ML-DSA (U4).

.. rst-class:: facts

:Adversary: ADV-D, network and registry
:Enforced at: no hook; ``shirudo bpm`` verifies in userspace, and the
   kernel verifies each loader (T1)
:Refusal: the ``bpm`` command fails and installs nothing
:Counters: none
:Tests: ``t7005``, ``t7013``, ``t7101``, ``t7102``, ``t7103``, ``t7104``,
   ``t7105``, ``t7106``, ``t7107``, ``t7108``, ``t7111``, ``t8005``
:Proofs: ``bpm-tar-header``, ``bpm-tar-octal``, ``bpm-archive-path``,
   ``bpm-oci-challenge``, ``bpm-oci-token``, ``bpm-oci-header``,
   ``bpm-oci-descriptor``, ``bpm-semver-model``, ``Shirudo.SemVer``,
   ``Shirudo.ArchivePath``, ``bpm-archive-path-model``,
   ``Shirudo.JsonString``, ``Shirudo.TreeSync``, ``bpm-tree-follows``,
   ``bpm-tree-sync-model``, ``bpm-tree-sync-application``,
   ``bpm-tree-sync-pending``, ``bpm-tree-recovery-model``,
   ``bpm-tree-state-pending``, ``bpm-tree-state-replay``,
   ``bpm-tree-reader``, ``json-string``,
   ``json-limits``
:Residual: R8, R9, U3, U4, U15

T8 Quantum-capable adversaries against the trust anchor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Embedded fleets keep trusting a certificate for years. A signature that
a future adversary could forge would let it install BPF on every device
that still trusts the old certificate. shirudo signs with ML-DSA-87
(FIPS 204) only. ``shirudo genkey`` makes nothing else, every operator
signature refuses a key that is not ML-DSA-87, and ``shirudo keys
vouch`` and ``shirudo keys add`` refuse another kind of certificate.
Digests are SHA-256 and SHA-512. :doc:`cryptography` lists every
algorithm and where it is used.

On the target, the pre-flight check ``cert_algorithm`` refuses a
certificate other than ML-DSA-87 in the key directory it reads. In the
initrd that is ``/etc/shirudo/keys``, not the runtime image's set that
``init`` enrolls (U4).

.. rst-class:: facts

:Adversary: a future adversary with a cryptographically relevant
   quantum computer and recorded signatures and traffic
:Enforced at: no hook; the operator's signing code and the pre-flight
   check ``cert_algorithm``
:Refusal: the signing command fails; ``init`` fails its pre-flight
:Counters: none
:Tests: ``t2001``, ``t2002``, ``t2004``
:Residual: R9, U4

.. _tm-t9:

T9 A target lying about its state
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``shirudo status``, the keepalive and the tamper counters are the
target's own account, and a compromised target says what root wants.
``shirudo attest`` makes the TPM speak instead. It produces a quote
over the selected PCRs, by default 0 to 7, 9 and 11 to 15, and a
certification of the register, both signed by the attestation key with
the verifier's nonce. The attestation key is an ECDSA P-256 primary
with a fixed template under the endorsement hierarchy. A credential the
verifier makes under the target's endorsement key (``shirudo attest
challenge``), and the target activates while attesting, proves that the
attestation key sits in the TPM whose endorsement key the evidence
carries.

``shirudo attest verify`` checks the nonce, the attributes of the
attestation key, its name against its public area and, with
``--ak-name``, against the pinned name. It checks the quote's PCR
digest, that the certification names the listed index and value, and
that both come from one TPM boot, with the same reset and restart
counts, as a restart clears the register too. It recomputes the index's
public area from the recorded PCR 9 and 11 binding values and the NV
writer's public key, so a recreated index fails. It replays the eventlog
to the certified value, checks that every event's digest derives from
its fields, and checks the PCR 9 anchor. With ``--cert`` and
``--upatch`` it computes the expected init event, with
``--expect-chain`` it compares the register, and with
``--expect-bind-pcr``, ``--expect-pcr`` and ``--expect-config-root`` it
compares the values the operator pins.
Which firmware, kernel and initrd values are acceptable is the platform
owner's policy.

The evidence boundary of :ref:`tm-trust-boundaries` applies: what is
not signed by the TPM is the target's account. Without ``--ak-name`` a
document can carry a software key's signatures (U1).
:doc:`/operate/run/attest` is the procedure.

.. rst-class:: facts

:Adversary: ADV-B and ADV-C
:Enforced at: no hook; the TPM signs and the verifier checks
:Refusal: ``verdict: fail`` from ``shirudo attest verify``, with the
   failed check named
:Counters: none
:Tests: ``t4003``, ``t4004``, ``t4102``
:Proofs: ``tpm-reader``, ``tpm-attest``, ``tpm-signature``,
   ``tpm-public``, ``attest-pcr``, ``attest-fields``,
   ``attest-name-digest``, ``config-evidence-parse``,
   ``config-evidence-verify``, ``Shirudo.Chain``, ``Shirudo.Events``
:Residual: R10, R11, U1, U9

.. _tm-t10:

T10 An attempt that leaves no trace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A refusal the operator never sees invites the next attempt. Each named
point at which a guard refuses counts the refusal in ``shirudo_tamper``,
an array map ``init`` creates, freezes and pins at every boot. One
point counts what it lets through: a signal to an authorized task from
a task without authority (``SealSignal``, T3). Only the
hooks add to it, and no task resets it from userspace. ``shirudo
status`` lists the counters that are not zero with their meaning,
``status --json`` carries them all, and so does the keepalive body,
which the TPM quotes, in its ``tamper`` list. The refusals of changes to
the running kernel (T6) count apart from those of shirudo's own state,
in ``shirudo_integrity``, which ``init`` creates, freezes and pins the
same way; ``status`` reports them in their own section and key, and the
keepalive in its ``integrity`` list.

A counter is evidence of an attempt, not of a compromise. Some
refusals move no counter: the kernel's signature errors, the guards of
the ``/run/shirudo`` tmpfs and the image mounts, the device-mapper and
mapping checks, the seccomp and memory checks, and refusals by another
LSM ordered before ``bpf``. Zero does not mean that nobody tried.
:doc:`tamper-counters` lists every counter, its hooks and the refusals
without one, and :doc:`integrity-counters` the integrity counters.

.. rst-class:: facts

:Adversary: ADV-A and ADV-B
:Enforced at: every hook that counts; :doc:`tamper-counters` and
   :doc:`integrity-counters` list them
:Refusal: the refused operation fails and its counter moves
:Counters: all, see :doc:`tamper-counters` and :doc:`integrity-counters`
:Tests: ``t6003``, ``t6108``
:Residual: R17

.. _tm-t11:

T11 Config and executable substitution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authority comes from the runtime image and settings come from the
config image, so each must be the one the operator built. Both are
dm-verity images. The runtime root hash comes from the bootstrap
settings in the initrd and is frozen in the identity map. A config root
carries a detached signature over its 64 lowercase hex characters, and
the kernel verifies it when shirudo creates the mapping.
:doc:`/internals/config-images` describes the formats.

``lsm.s/bdev_setintegrity`` classifies each dm-verity mapping when the
kernel sets its root. A root equal to the frozen runtime root makes the
device a runtime device. A config device needs an authorized task that
staged that exact root for itself first, and the stage is used once.
Other mappings gain no status. Only a file directly on a runtime device,
on a read-only superblock, grants authority at exec (T3).

``lsm/file_ioctl`` and ``lsm/file_ioctl_compat`` refuse every
device-mapper control ioctl other than the read-only ones to tasks
without authority, through old and inherited descriptors too, and for
unrelated device-mapper devices as well. The mount hooks refuse every
caller an unmount, a move, a mount over or a remount of the runtime
image. For a config image they refuse a remount to every caller and the
rest to tasks without authority.

shirudo validates the verity superblock, the format and the sizes,
creates or validates a strict read-only mapping, and reads every data
block of a config mapping before it parses or measures it. It reads
the config's files through the held root and refuses symbolic links and
special files. A config never authorizes an executable, supplies no
bootstrap key or TPM setting, and cannot enroll a key while the target
runs: a live activation that would trust a key the ``.bpf`` keyring does
not hold refuses before it changes anything.

The configured certificate set determines which keys can sign a config (A7).

.. rst-class:: facts

:Adversary: ADV-B and ADV-C
:Enforced at: ``lsm.s/bdev_setintegrity``, ``lsm/bdev_free_security``,
   ``lsm/file_ioctl``, ``lsm/file_ioctl_compat``, ``lsm/sb_mount``,
   ``lsm/move_mount``, ``lsm/sb_umount``, ``lsm/sb_remount``,
   ``lsm/key_permission``, ``lsm.s/bprm_check_security``,
   ``lsm/mmap_file``, ``lsm/file_mprotect``
:Refusal: ``EPERM`` or ``EACCES`` from the mapping, ioctl and mount
   calls; ``shirudo image update`` and ``init`` fail
:Counters: ``KeyringWrite``; the mapping, ioctl and image mount
   refusals move none
:Tests: ``t5101``, ``t5102``, ``t5103``, ``t5104``, ``t6101``,
   ``t6113``, ``t6127``, ``t6130``, ``t6131``, ``t6132``
:Proofs: ``config-image``, ``image-bootstrap``, ``image-path``,
   ``dm-names``
:Residual: R5, R14

T12 Interrupted image activation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A config activation changes keys, repositories and revocations and
extends the config PCR. An interruption half way must not leave a
target that runs one config while its records claim another.
``shirudo image update`` makes the candidate and the pending selection
durable before it extends the PCR. A validation failure before that
point leaves the active config in use. After it, including on an
ambiguous TPM response, the target needs a manual reboot. A resume from
suspend or a TPM restart is none: the TPM boot is the TPM's reset count,
which neither changes, so a hand-run ``init`` after one records nothing.
The target keeps running, shirudo never reboots it, refuses further
state changes and config attestation, and ``shirudo status`` reports
``reboot-pending``.

At the next boot, ``init`` verifies the selected image again, reads its
whole mapping, extends the config PCR with a fresh boot event and
applies revocations before it restores upatches. It records completion
only after startup succeeds. A selected image that is missing or
invalid fails ``init`` rather than falling back to an older config.

.. rst-class:: facts

:Adversary: ADV-B, and faults such as a crash or power loss
:Enforced at: no hook
:Refusal: state-changing commands refuse while the activation is
   pending; ``shirudo status`` reports ``reboot-pending``
:Counters: none
:Tests: ``t4004``, ``t5105``
:Proofs: ``Shirudo.ConfigActivation``, ``config-update-follows``
:Residual: R4, R14

T13 Reading or draining upatch state
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The maps of upatches hold observations, and shirudo's own maps hold the device
records and the identity. A read-only map descriptor reads that state,
and a serializer program run with ``BPF_PROG_TEST_RUN`` drains an
interval before the export takes it. Either lets root read or erase what
the operator relies on.

``lsm/bpf_map`` refuses every map descriptor to tasks without runtime
authority: a writable one as ``MapFdWrite`` and a read-only one as
``ObjGet``. ``lsm/bpf`` refuses the routes to a descriptor,
``BPF_OBJ_GET`` and ``BPF_MAP_GET_FD_BY_ID`` (``ObjGet``), and
``BPF_PROG_TEST_RUN`` (``ProgRun``), and with ``BPF_MAP_UPDATE_ELEM``
and ``BPF_MAP_FREEZE`` the writing and freezing of a map
(``MapWrite``). ``lsm/file_open`` refuses opening a
pin as a file, through which bpffs would print a map's contents
(``ObjGet``). A writable memory mapping of an arena needs a writable
descriptor. A process whose executable is not on the runtime image
therefore neither reads nor drains the maps, and reads the identity
only through a runtime command such as ``shirudo status``.

The boundary is the command interface: root can run the runtime binary,
and ``shirudo upatch map`` drains a serializer unless ``--peek`` is
given (R2).

.. rst-class:: facts

:Adversary: ADV-B, root on the target without the signing key
:Enforced at: ``lsm/bpf``, ``lsm/bpf_map``, ``lsm/file_open``
:Refusal: ``EACCES`` from ``bpf()`` and from opening a pin
:Counters: ``ObjGet``, ``MapFdWrite``, ``MapWrite``, ``ProgRun``
:Tests: ``t6107``, ``t6108``, ``t6109``, ``t6110``
:Residual: R2

T14 Substituting the TPM
~~~~~~~~~~~~~~~~~~~~~~~~

shirudo reaches the TPM through a device node it opens by path. In image
mode it accepts only a device TCTI, by default ``device:/dev/tpmrm0``,
set in the authenticated bootstrap settings. Root can put another
device at that path in a mount namespace of its own, an emulator for
instance, and the emulator would answer every check that compares
public values, since the index name, the policy and the reset count are
in the readable init record.

Every connection recreates the ECC endorsement primary and, while
enforcement is active, compares its name with the one ``init`` froze.
That primary salts HMAC and policy sessions. Successful TPM replies,
including the extension acknowledgments and NV, PCR and clock readbacks,
are authenticated. A device that forwards the key creation but suppresses
an extension cannot produce a valid success response or fabricate the
readback. Session failures are not retried as measurements.

Initial enrollment trusts the authenticated initrd and the kernel TPM
device it opens (A1, A6, A8). An unreadable frozen identity, a missing pin
or a different session key fails rather than enrolling a replacement.
``lsm/tpm_command`` refuses unauthorized extensions that reach the real
driver; sessions do not prevent denial of service by dropping requests.

.. rst-class:: facts

:Adversary: ADV-C, root with mount-namespace and device control
:Enforced at: ``lsm/tpm_command`` for commands that reach the driver;
   pinned-key and session-response checks in userspace
:Refusal: the TPM operation fails; measuring commands refuse
:Counters: ``TpmExtend`` for a refused extension, ``TpmWrite`` for any
   refused command; none for a substituted device
:Tests: ``t4005``, ``t4103``, ``t6125``
:Proofs: ``tpm-public``, ``tpm-kdf``
:Residual: trusted bootstrap (A1, A6, A8); denial of service

T15 Installing an unsigned Java agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A Java upatch installs a jar that every JVM started with shirudo's
options loads as an agent, with the JVM's privileges. Root who could
install a jar of its own there, change the installed one, or have a BPF
artifact taken for a Java one, or the reverse, would run code the
operator never signed under a name the register records as signed.

No kernel check covers a Java upatch: it has no loader. ``upatch load``
and boot restore check its signature over the signed data in userspace
with OpenSSL, against the unrevoked certificates of the authenticated
runtime's set, then require the signer to be a key the ``.bpf`` keyring
holds, found by the description the kernel gives the key, not by its
material. Config activation already refuses a set the keyring does not
hold, so the lookup keeps the Java check from resting on that alone. A
key a revocation unlinked signs no Java upatch, as it signs no BPF one;
a key a later config drops without revoking it stays in the ring and
still signs a BPF upatch, but no Java one. They also check its signed
name, signed type and payload digest. The header's type is not signed,
so the reader refuses a file whose type differs from the signed ``PTYP``
section; a BPF artifact carries none and cannot be relabelled Java. A
Java artifact relabelled BPF is refused by that check too. The two
signatures cover one byte stream under one key with no type in it,
though: signed Java data split into a loader and data has a section
directory that no longer ends at its trailer, reads as BPF without
signed sections, and is then refused because it has no signed name,
and its bytes are no loader the verifier accepts (D10). The jar is written
sealed under ``/run/shirudo-java``, which ``init`` makes and labels
before anyone else can, outside the state root, which stays ``0700``.
The seal refuses a write, rename, unlink or label change of the jar, and
the removal of its directory, to every task without runtime authority.
Boot restore writes the jar from the archive at each boot, and a later
run of ``init`` in the same boot refuses a jar that is missing or
another rather than writing it again, which would hide that JVMs started
without it. An unload or a purge leaves a jar in its place whose agent
does nothing, which is part of the shirudo binary and stays until the
next boot, so that a JVM whose options still name the jar starts. Its
load and unload are measured as ``java_load`` and
``java_unload`` events, which no BPF event can be read as, and
``status`` reports a measured agent whose jar is missing or another.

.. rst-class:: facts

:Adversary: ADV-B, root on the target without the signing key
:Enforced at: ``java_upatch_verify()`` and the reader's type check in
   userspace; ``lsm.s/file_open`` and the seal's inode hooks for the jar
:Refusal: ``signature_rejected`` or ``parser_rejected``; ``EACCES`` on
   the jar
:Counters: ``SealWrite``, ``SealUnlink``, ``SealRename``, ``SealSetattr``,
   ``SealXattr`` for the jar; none for a refused load
:Tests: ``t3014``, ``t3114``
:Proofs: ``upatch-header``, ``upatch-signed-sections``, ``chain-events``,
   ``Shirudo.Events``
:Residual: R2, R24

Residual risks
--------------

Each residual risk is known and bounded, and each says how an operator
detects it. Several stay silent on the target and show only in
evidence a verifier checks.

R1 Unload runs in userspace, and directives are reusable
   The kernel's ``bpf_sys_bpf()`` cannot detach a link or remove a pin,
   so a signed unload directive authorizes and shirudo removes the pins
   in userspace. The directive's target name and expected payload are
   signed, so root cannot aim it at another upatch. Root keeps the
   moment: every directive ever published is root's to apply at any
   time. A directive is not bound to the signer of the load either. Any
   key in the ``.bpf`` keyring that signed a directive with the right
   name and payload digest, both visible in ``shirudo status`` and the
   eventlog, unloads the upatch. Detection: every application is an
   unload event in the register. Mitigation: D5.

R2 The command interface of the runtime binary is the boundary
   Root can run any command of the runtime binary. It can load any
   signed artifact (R16), apply any published directive (R1), drain a
   serializer with ``shirudo upatch map`` and send the output where it
   chooses, and hold the lock files shirudo serializes on. No hook
   refuses signals, so root can also stop a running command, which
   ``lsm/task_kill`` counts (``SealSignal``) and which keeps open
   whatever descriptors it holds (U17); a load stopped before its
   extend is reported and undone (T5). A stop by the kernel, through
   ``cgroup.kill``, the OOM killer, a pipe root closes or the cgroup
   freezer, passes no hook and is not counted.
   ``CAP_SYS_RESOURCE`` can rewrite a process's executable link, which
   ``lsm/task_prctl`` refuses and the mark does not depend on. The
   initrd's bootstrap binary and the memory of authorized tasks stay
   in the TCB. Detection: loads and unloads are measured; drains,
   stops and lock holding are not.

R3 Pins depend on the mount tree
   The pins hold the links through the bpffs superblock. The guards of
   T2 cover unmounts of the bpffs and of mounts above it in ``init``'s
   namespace. A private copy of the tree in another namespace is any
   process's to drop, which releases nothing. Legacy ``mount(2)`` with
   ``MS_MOVE`` reaches ``lsm/sb_mount`` with the target only, so the
   source mount is not checked (D8). ``pivot_root(2)`` is not hooked,
   and ``mount_setattr(2)`` has no LSM hook at all, so root can change
   mount attributes and propagation, making the bpffs read-only for
   instance. A mount over ``/run`` or an ancestor hides the pins without
   releasing them: enforcement continues, ``shirudo status`` reports the
   LSM as not attached, and ``upatch load`` and ``upatch unload`` refuse
   ``tampered`` with the message ``lsm_detached`` in their pre-flight.
   The walk's bounds refuse every unmount of a tree they cannot cover.
   Mitigation: D7.

R4 Config PCR writers are not authenticated
   The config PCR, one of 0 to 15 other than 9 and 11 chosen in the
   bootstrap settings, is extended with ``TPM2_PCR_Extend``, which
   ``lsm/tpm_command`` does not restrict. Any root process can extend
   it. Garbage makes the config history fail its replay, a denial of
   service. The digest of a valid activation, which is public, records
   an activation that never happened. The verifier also takes the
   value the history starts from out of the evidence rather than
   requiring zero. A fresh nonce and a genuine quote prove neither who
   extended the PCR nor that an activation completed. Root also decides
   when the TPM's boot changes. ``TPM2_Clear``, which needs only the
   lockout authorization that shirudo leaves empty, puts the reset count
   back to zero, so a later TPM boot can carry an earlier one's. One in
   the middle of an activation lets ``init`` extend the same activation
   a second time in one PCR lifetime, and a repeated reset count lets a
   record name the TPM boot it is in while the PCR does not hold its
   replay, which refuses commands until a reboot. A suspend to RAM, or a
   TPM restart that clears the PCR, keeps the TPM boot and changes
   nothing but refusals. The Lean proofs of the activation that count
   extensions or explain a refusal assume neither
   (``Shirudo.ConfigActivation``). Detection: none reliable. Mitigation:
   D1. ``config.nvpcr``
   narrows it: the config NvPCR is extended only by the full role and
   starts at a known value, which the verifier requires; that an
   activation completed is still not proven.

R5 The boot chain and process memory stay trusted
   dm-verity verifies runtime blocks as they are read. It does not
   protect process memory, and it trusts the UKI and the kernel that
   chose the root hash (A6). ``SHIRUDO_VERSION_ID`` keeps an operator
   and a target of different builds apart; it authenticates nothing.

R6 A failed or skipped init leaves the target unprotected
   There is no fallback mode. When ``init`` fails in the initrd, or
   the unit does not run, the boot continues without enforcement and
   without a bound register (U11). Detection: attestation fails for
   want of an init record, and ``shirudo status`` reports the LSM as
   not attached.

R7 The boot window before init
   Before ``init`` attaches ``lsm/bpf`` in the initrd, any process in
   the initrd can load and attach BPF, and what it leaves attached
   stays. The initrd is measured into PCR 9 and, on a measured UKI
   boot, its phases into PCR 11, and it is in the TCB (A6). Without
   the phase measurements PCR 11 holds no phase, and a verifier tells
   an initrd binding from a later one by PCR 9 alone. A first ``init``
   from the root file system runs after every process before it, reads
   its settings from the root file system's ``/etc/shirudo/shirudo.conf``
   and binds the register after ``leave-initrd``. ``--expect-bind-pcr``
   with the initrd's values rejects such a binding.

R8 Registry withholding and replay
   A registry or a network adversary can withhold any content and
   serve any older, validly signed index or package. The target keeps
   the last index that verifies, and nothing orders one index before
   another or binds it to the registry it came from. ``shirudo bpm
   list`` shows the target's own state, and a repository update is not
   measured. ``bpm push`` builds the next index from the one the registry
   serves, so an older one makes the operator sign an index without the
   packages added since; a registry that claims to have none is refused
   unless ``--new-index`` is given. ``bpm tree append`` builds the next
   publication on the one the registry serves the same way, so an older
   one makes the operator sign a second branch of the tree. It extends
   only the tree ``--tree-id`` names, which an existing tree requires,
   so a registry that serves another tree the key signs in its place, a
   canary tree at ``stable``, is refused (``t7005``, ``t7008``). A target
   that processed an operation the second branch does not have refuses
   it, as its operations up to the target's cursor do not fold to the
   ``history_root`` the target holds, in a segment and at a segment's
   base alike; a target behind the point where the branches part takes
   either. A registry can still withhold the latest publication or a
   sealed segment, which stops a walk, and keep serving a stale tag,
   which a target takes for current until a later one reaches it. A
   registry that answers slowly holds each transfer of a timer's
   command, and the config operation lock every other command waits for
   up to 30 seconds, until that transfer's deadline: a minute plus the
   time its largest response, 16 MiB, or its package's size, takes at
   128 KiB a second (``t7010``).
   Detection: compare the upatch payloads and tree operations that
   ``attest verify`` certifies with what you published, and the pushed
   index with the versions you released.

R9 Classical pieces
   The WebPKI certificates of registries and collectors authenticate
   the transport, not the artifacts. Hosts opted into
   ``tls.classical_hosts`` get a classical key exchange, so recorded
   traffic to them may be exposed to a future quantum-capable
   adversary. The attestation key is ECDSA P-256, because TPMs sign
   with nothing post-quantum today, the NV writer's authorization is
   RSA-3072, and credential activation uses the endorsement key's RSA
   or ECC algorithm. The evidence is therefore classical even though
   the artifacts it describes are not.

R10 Endorsement key trust
   Credential activation ties the attestation key to the endorsement
   key in the evidence, and the endorsement certificate ties that key
   to a manufacturer. ``shirudo attest challenge`` makes no challenge
   unless the certificate chains to the issuers given with
   ``--ek-ca``, the key is pinned with ``--ek-name`` from an inventory,
   or the operator waives the check with ``--trust-presented-ek``,
   which proves only that the same party answers each time. Virtual
   TPMs usually have no certificate. Which issuers to trust is the
   operator's decision.

R11 The anchor shares PCR 9
   PCR 9 also carries the initrd measurements and systemd's NvPCR
   events. ``attest verify`` proves the anchor exactly only when nothing
   is measured into PCR 9 after ``init``; otherwise it reports a note
   and leaves the replay of the systemd measurement log, which the
   evidence carries, to the verifier. ``--strict-anchor`` turns the
   note into a failure. Mitigation: D3.

R12 A process before init can bind first
   A process that runs before ``init`` in the same boot phase can define
   and write the register first. ``init`` then rebinds it with a
   warning, which discards what was written. Anything the earlier
   process extended into PCR 9 changes the binding value, which
   ``--expect-bind-pcr=9`` with the expected value rejects. A record of
   this boot that such a process leaves names an NV writer it cannot
   know, since ``init`` draws the writer's seed at random each boot, and
   ``init`` then refuses to bind, a denial of service. From the initrd
   such a process is part of the TCB (A6); from the root file system it
   is R7.

R13 Revocation reaches a target only through a config
   A revocation arrives with a signed config that the target activates,
   live with ``shirudo image update`` or at boot. ``shirudo keys
   revoke`` refuses. A live activation unlinks the key from ``.bpf``,
   measures a ``key_revoke`` event and then purges the key's upatches,
   each with an unload event. If that extension fails, the key stays
   unlinked, the revocation is unmeasured and the purge does not run.
   At boot the revoked key is not enrolled, and the init event's
   certificate list shows it. A target that has not activated the
   config still trusts the key. Historical vouches are U13.

R14 Configs roll back
   shirudo accepts any validly signed config. A live activation cannot
   add a key to ``.bpf`` this boot, but it can roll back every other
   setting: repositories and their certificates, the tree subscription,
   export endpoints, the eventlog limit and revocation records, and the
   selection persists across reboots. The selection journal under
   ``/var/lib/shirudo/config-update`` is not authenticated, so a change
   to it between boots selects any config in the cache under
   ``/var/lib/shirudo/images``, its trusted set included. The config
   certificate itself changes only with the runtime image and a reboot.
   Detection: ``--expect-config-root`` with ``--expect-config-pcr``.
   Mitigation: D2.

R16 Any artifact ever signed loads at any time
   There is no version floor, no expiry and no per-target
   authorization. Neither shirudo nor the kernel checks a certificate's
   validity period. Root can roll a upatch back to an older vulnerable
   version or load a signed debug upatch. Detection: the load is
   measured, and a verifier with an expected state sees it. The only
   way to retire one artifact is to revoke the key that signed it.

R17 Telemetry has no proof of origin
   Map snapshots are unsigned and not bound to the TPM. A keepalive
   carries a quote of the SHA-256 of its body by the attestation key of
   ``attest``, created for each keepalive, over no PCR, and
   ``shirudo-quote-check`` verifies it without a TPM. A quote that
   checks proves that the body is unchanged since that key signed it,
   and its clock orders the keepalives of one key. A keepalive sent
   again checks as it did the first time: a backend has to take a
   record's age from when its clock first arrived, as the example
   backend's check 2 does, or a silent node reads as alive. It does not prove
   that the key lives in a genuine TPM: only ``attest challenge`` ties
   the key to an endorsement key, and a backend treats every node as
   ``untrusted`` until a future workflow does that. Nor does it vouch
   for the body: root on the target can have the TPM quote a body of
   its own. ``host.name`` is the target's host name, and the
   credentials come from files root reads. ``map_export.otel_insecure``
   turns certificate verification off. Root can withhold, drain or
   forge telemetry. Only ``attest verify`` is evidence.

R18 BPF outside the gates
   ``lsm/bpf`` and ``lsm/bpf_prog_load`` admit every call whose
   ``kernel`` argument is set. That includes in-kernel light skeletons
   loaded through ``kern_sys_bpf()``, such as the ``bpf_preload`` module,
   which a signed module can bring in (A4). Classic BPF, for seccomp
   filters and ``SO_ATTACH_FILTER``, does not use ``bpf()``. Program
   descriptors other than XDP stay open to root, and the attach paths outside
   ``bpf()`` that take one, socket options and netlink among them,
   accept only program types those paths support. The operator's build
   refuses sections of those types except XDP, whose descriptors
   ``lsm/bpf_prog`` guards; the kernel does not refuse these types in a
   signed loader.

R19 Raw device and offline writes bypass the seal
   The seal guards file operations. A write to the block device under
   ``/var/lib/shirudo`` while it is mounted (A10), or any change between
   boots, bypasses it. Removing the label from the state root offline
   makes the next bootstrap run of ``init`` label everything under it,
   and so does another tree at ``/var/lib/shirudo`` on the next boot,
   which root chooses on the running system too: the root file system's
   ``fstab`` decides what the initrd mounts at ``/var`` and below
   (``x-initrd.mount``). Only the rename of a directory above the state
   root on its own file system is refused (T3).
   Across reboots only signatures and the register protect state:
   upatches are verified at load and measured in the init event, and
   the package, tree and config selection state is not authenticated.

R20 The TPM owner password is not a secret on the target
   ``tpm.owner_auth`` lives in the runtime image's ``shirudo.conf``,
   where root reads it. shirudo uses it in HMAC authorization, but this
   does not hide it on disk. Root can undefine the register, which makes
   every measuring command refuse until the next TPM reset, or use the
   owner hierarchy.
   An image shared across a fleet shares the password.

R21 upatches can be neutralized by changing their targets
   A upatch stays loaded and measured while root makes it ineffective:
   by unloading the module a kprobe targets, by replacing the binary a
   ``uprobe``, ``uretprobe``, ``uprobe.multi`` or ``uretprobe.multi``
   target names with a new inode. Disabling kprobes through debugfs is
   a debugfs write, which ``bpf2``'s lockdown refuses (A4). These
   are readings of the kernel source and are not tested.

   XDP coverage is reconciled, not continuous. A device added after load
   runs without the upatch until ``upatch reconcile`` next runs, and is
   unfiltered until then: normally seconds after its udev event, and up to
   one pass plus 60 seconds when udev gives no signal, as for a veth
   peer moving namespace. A device stays uncovered while its XDP slot is
   occupied, it has no native XDP, its driver refuses the program, or
   root stops the timer and the udev rule. ``status`` lists every such
   device under ``XdpCovered`` with the reason the device reports and
   gives the verdict ``degraded``, which the keepalive carries; root
   can stop the keepalive as well, which its collector sees as silence.
   At boot restore a device whose driver refuses, or that a upatch
   restored before holds, fails ``init``: the register stays unbound, so
   attestation fails, and that upatch and every archive after it in name
   order stay unloaded that boot. Neither a setting that survives a
   reboot, in the NIC's firmware or the hypervisor, nor a second upatch
   that selects the device can therefore take it out of a upatch
   unseen, at the price of a host that boots without those upatches. A
   device whose driver name or devlink port cannot be read is the
   exception: no class can be given to it, and any device's failing
   lookup would otherwise stop ``init``, so it sits out with a warning
   and ``status`` lists it as ``not classified`` under every XDP
   upatch. A veth end moved to another namespace
   keeps its link, so a pair can hold two attachments, one of them running
   in that namespace. Reconcile adds no register event: TPM evidence covers
   the signed class mask and loaded artifact, not the device inventory or
   which devices are covered. ``t3111`` and ``t3112`` exercise selection,
   reconcile and unload; driver behavior across a namespace move is
   tested only for veth.

   Every XDP program is loaded with multi-buffer support and a selected
   device must report it. At boot restore one that does not fails
   ``init``. After boot it stays uncovered, with a warning, and ``status``
   lists it. The check is made at attach only: a device that later
   stops reporting it keeps its link, as a bond that later enslaves such a
   device does, and what happens to a frame too large for one buffer is
   then the driver's choice. It may drop the frame or never run the
   program on it.

   No record says which per-device XDP link pins should exist, because
   they come and go with devices. A pin that disappears while its device
   remains looks like a device not yet attached: ``init`` and ``status``
   do not report it, and the next reconcile attaches again. This assumes
   the private bpffs guards hold: removing or renaming a pin needs runtime
   authority, and an attempt without it is refused and counted as
   ``PinUnlink`` or ``PinRename``. A task that has that authority, or gets
   past the guards, can detach an XDP link unreported until the next pass.
   Every other pin a upatch must hold is checked.

R22 Labeled inodes are interchangeable
   The label carries no identity. Any labeled inode passes shirudo's
   checks at any sealed path, and ``lsm/sb_mount`` does not guard the
   file system that holds ``/var/lib/shirudo``. In a mount namespace of
   its own, root can bind one labeled inode over another sealed path
   for a shirudo command it runs there. U9 is one consequence; others
   are a hidden eventlog, which makes measuring commands fail, and
   package or tree state read from the wrong file. What root can bind is
   what shirudo labeled: no target command writes a temporary file,
   which a sealed directory bound over ``/tmp`` would have labeled with
   content from a registry (``t7002``). This is a reading of
   the code and is not reproduced. A bind mount over the state root in
   ``init``'s namespace, an idmapped one among them, was reproduced:
   every command refuses the state as foreign from then on. The lock
   that keeps the register in step rests on no label: a lock file
   beside the eventlog would let a command in root's namespace lock a
   decoy and undo the pins of a load still in flight in another, which
   then measures an upatch nothing runs. The register lock is the root
   of the private bpffs, which takes no mount and no entry from root, so
   a command in any namespace waits for the same inode (``t6128``). The
   bpm lock, ``locks/bpm.lock``, still rests on a label: two package or
   tree commands under a decoy can interleave their own state, while
   each step they measure still waits for the register lock.

R23 Policy labels follow the inode
   A policy label is an xattr of the executable's inode, applied at
   every load and boot restore of the upatch that declares it. A copy
   of the executable, or the new inode a package upgrade or an editor
   leaves in its place, carries no policy until the upatch is loaded
   again, and neither does a file that comes to match a pattern after
   the load. A hard link or a rename that root makes of an inode
   without the seal label moves the policy to another path, and a
   regular file root gives a name a pattern matches is labeled at the
   next load. A file
   system that root makes and mounts, a loop image say, carries the
   xattr on its own executables, written where no seal ran, and an
   execution from it takes whatever bits root put there. A task
   keeps the bits it accumulated, a socket keeps the snapshot of its
   creator, and a socket passed from another task carries that task's
   bits. Root can therefore give its own processes any bits: an
   enforcement upatch decides what an execution without policy bits
   may do, lets a bit restrict rather than exempt, and the operator
   reloads after a change to a labeled path. Detection: none on the
   target.

R24 A Java agent reaches only the JVMs its options reach
   The options that name the agents are
   ``/run/environment.d/shirudo.conf``, which is not sealed, and which
   systemd's user managers read. Root can change or remove it, set
   ``JAVA_TOOL_OPTIONS`` for a JVM of its own, or start one without a
   user manager, and a JVM running when the agent loads keeps the agents
   it started with. A user manager reads the options when it starts: one
   started before a load starts its JVMs without the agent until it
   restarts, and another ``environment.d`` file can set
   ``JAVA_TOOL_OPTIONS`` over shirudo's. An agent is Java code in the JVM it guards, which
   the application can undo. A Java upatch is therefore a mitigation in
   the applications that start with it, not a boundary against root,
   which only a BPF upatch is. Detection: a JVM's ``-javaagent``
   arguments, ``jcmd <pid> VM.command_line``; none from shirudo.

Threats to resolve
------------------

These gaps are in the code today and are not closed. Each entry says
what it affects, the consequence, whether it is confirmed in the code
or a reading of a code path that is not reproduced yet, and what a
deployer can do meanwhile.

U1 Verification passes without a pinned key or an expected state
   :Affects: ``shirudo attest verify``.
   :Consequence: ``--ak-name`` is optional and its absence only warns;
      the document then authenticates nothing, since a software P-256
      key can carry the required attribute bits. Without ``--cert``,
      ``--upatch`` or ``--expect-chain`` the register's value is
      reported, not checked. ``--require-initrd`` reads ``bound_in``,
      which no digest covers.
   :Status: Confirmed in code.
   :Meanwhile: Always pass ``--ak-name``, an expected state,
      ``--expect-bind-pcr=9=<value>`` and ``--expect-bind-pcr=11=<value>``,
      and ``--expect-config-root`` with ``--expect-config-pcr``. See
      :doc:`/operate/run/attest`.

U3 The environment reaches authorized processes
   :Affects: The bpm and export units and any runtime command root
      starts.
   :Consequence: ``BPM_OCI_SCHEME=http`` turns TLS off,
      ``BPM_OCI_CA_FILE`` adds a trust anchor, proxy variables redirect
      the traffic, and credentials come from the environment and auth
      files. The environment files of the shipped units are writable
      by root. ``TSS2_LOGFILE`` (tpm2-tss) and ``SSLKEYLOGFILE``
      (libcurl), which open a file root names with the process's
      authority, are refused on a target like shirudo's own overrides
      (``t6136``): with the first set, ``shirudo status`` wrote the
      library's log into a sealed file. The personality the caller sets
      is dropped at start (``t6151``): under ``UNAME26``, ``uname()``
      reported a 2.6 release to the tree selector, and an operation it
      skipped for that release stayed skipped.
   :Status: Confirmed in code for shirudo's own variables; the library
      log file was reproduced on a test VM and is refused now.
   :Meanwhile: Keep ``/etc/shirudo/bpm/environment``,
      ``/etc/shirudo/map-export.env`` and ``/etc/shirudo/init.env``
      absent or empty and owned by root, and watch who runs runtime
      commands.

U4 Signatures other than ML-DSA-87 are accepted in places
   :Affects: Repository indexes, tree publications and the trust set
      ``init`` enrolls.
   :Consequence: Index and tree signatures verify with whatever
      algorithm the certificate holds, and no step checks that a
      repository certificate is ML-DSA-87. The pre-flight check
      ``cert_algorithm`` runs on the initrd's ``/etc/shirudo/keys``,
      not on the runtime image's certificate and the vouched signers
      that ``init`` enrolls, and the kernel accepts other algorithms in
      ``.bpf``.
   :Status: Code-path reading, not reproduced.
   :Meanwhile: Use only certificates that ``shirudo genkey`` made, for
      repositories too.

U6 The eventlog becomes unreadable at 8 MiB
   :Affects: Every reader of the eventlog: replay, ``shirudo status``,
      ``shirudo attest`` and ``init``.
   :Consequence: The readers stop at 8 MiB, ``eventlog.max_bytes`` has
      no default, the log is never rotated, and the ``tree_op`` and
      ``key_revoke`` events do not check the limit. Root can grow the log by
      applying published load and unload pairs. Past 8 MiB, status,
      replay and attestation fail across reboots. With a limit set,
      measuring commands and ``init`` refuse ``eventlog_full`` instead.
   :Status: Confirmed in code for the limits; the effect is a code-path
      reading, not reproduced.
   :Meanwhile: Watch the size of ``/var/lib/shirudo/eventlog``.

U7 The shipped timer units run the host binary
   :Affects: ``shirudo-keepalive.service``,
      ``shirudo-map-export.service``,
      ``shirudo-bpm-repo-update.service`` and
      ``shirudo-bpm-tree-sync.service``.
   :Consequence: Only ``shirudo.service`` receives the drop-in that
      ``shirudo-gen-runtime --unit-output`` generates. The others start
      ``shirudo`` from the root file system, which has no runtime
      authority: it cannot open the identity pin, so the command fails
      once enforcement is live and moves ``ObjGet`` at every run.
   :Status: Confirmed in code; the failure of each unit is a code-path
      reading, not reproduced.
   :Meanwhile: Install a drop-in for each of these services that
      starts its commands from the runtime image, as the test VM does
      in :src:`testing/vm/guest.sh`.

U9 init can rebind the register after hiding this boot's record
   :Affects: The one-binding-per-reset rule (T5).
   :Consequence: ``init`` decides whether it bound the register this
      boot from the eventlog and the boot ID it reads by path in its
      mount namespace. When it finds no record it undefines and
      redefines the register under the current PCR values (R22). Once
      the earlier init record is dropped from the document, the evidence
      of such a binding passes every check except a pin of the binding
      PCRs.
   :Status: Code-path reading, not reproduced.
   :Meanwhile: Always pass ``--expect-bind-pcr=9`` and
      ``--expect-bind-pcr=11`` with the initrd's values, or
      ``--expect-pcr=9`` with the predicted value.

U10 Kernel prerequisites are not checked
   :Affects: A5, A9 and A10.
   :Consequence: A target with 32-bit compatibility, with a resume
      device in its UKI or with writes under mounted file systems
      allowed initializes without an error and without the protection
      those assumptions give.
   :Status: Confirmed in code: the pre-flight checks none of them.
   :Meanwhile: Build the kernel and its command line as
      :doc:`/operate/plan/hardening` describes.

U11 The boot continues when init fails
   :Affects: ``shirudo-initrd.service`` and the root file system's
      ``init`` (R6, R7).
   :Consequence: The initrd unit is wanted by ``initrd.target`` and has
      conditions, so a failure or a skip lets the target boot
      unprotected. A first ``init`` from the root file system is not
      refused and takes its settings from the root file system. An
      ``init`` that crashes once it has pinned the identity map leaves
      the guards it attached so far, and every later ``init`` of that
      boot refuses, so enforcement stays partial until the next reboot.
   :Status: Confirmed in code; what a crash leaves is a code-path
      reading, not reproduced.
   :Meanwhile: Attest every target after every boot with the bind PCRs
      pinned, and treat a missing keepalive as a signal. A deployer who
      prefers a halted boot can add an ``OnFailure=`` drop-in to
      ``shirudo-initrd.service``; this is not tested.

U13 A revoked signer's historical vouches remain valid
   :Affects: Vouched keys (R13).
   :Consequence: Vouches carry no time. A revoked key's vouch for another
      key still admits it when a config lists that key. This supports
      planned rotation but does not distinguish a legitimate earlier
      vouch from one made with a compromised signing key.
   :Status: Confirmed in code. Rotation preserves this existing rule.
   :Meanwhile: When a signer is compromised, also remove or revoke every
      dependent key whose authority should no longer be trusted. A
      planned overlap is not sufficient compromise recovery by itself.

U15 Certificates are fetched without a pin
   :Affects: ``tools/gen-initrd/install.sh --cert <url>`` and
      ``shirudo bpm key add oci://...``, which image mode refuses on a
      target.
   :Consequence: The certificate installed is whatever the URL served.
   :Status: Confirmed in code.
   :Meanwhile: Pass a local file after checking its fingerprint.

U16 Boot restore is not all or nothing
   :Affects: ``init`` (T6).
   :Consequence: ``init`` restores archived upatches in name order and
      stops at the first failure. The upatches it already restored stay
      attached and pinned while no register is bound, so they run
      unmeasured.
   :Status: Confirmed in code.
   :Meanwhile: Treat a failed ``init`` as an incident; attestation fails
      for want of an init record. See
      :doc:`/operate/troubleshoot/incident-tampered`.

U17 A stopped runtime command keeps its descriptors
   :Affects: The descriptor checks of T2.
   :Consequence: Runtime commands open link pins for short checks. No
      hook refuses signals, ``lsm/task_kill`` only counts them
      (``SealSignal``), and the kernel's own signals and the cgroup
      freezer pass uncounted, so root can stop such a command while it
      holds a link descriptor, and that link then stays attached after
      its pin is removed by an unload or a revocation.
   :Status: Code-path reading, not reproduced.
   :Meanwhile: A stopped shirudo process is visible in the process
      list; compare the loaded links with the measured set when one is
      found.

U20 The keepalive reports only the last 512 tree operations
   :Affects: The keepalive body (``base_seq``, ``base_root``, ``mask``)
      and what a backend can check of a node's loaded set.
   :Consequence: The body gives the node's outcome for each operation
      of a window of at most 512 operations up to the head of its tree.
      A backend that first hears from a node after the tree has grown
      past that window never learns which earlier operations the node
      applied. It can check that each window continues the last one
      and compare the node with nodes of the same labels, but not which
      upatches added before the window the node should run, so it
      cannot check ``set_sha256`` against them. Every node that joins a
      tree of more than 512 operations is in that case. The node keeps
      every outcome in ``upatch-tree/outcomes``; only the body leaves
      them out.
   :Status: Confirmed in code.
   :Meanwhile: Compare such a node with its peers, and attest it with
      ``shirudo attest`` when its set matters: the register measures
      every upatch it loaded. See :doc:`/operate/run/attest`.

Deferred mitigations
--------------------

These are in scope and not built yet:

D1 Authenticated config PCR writers
   Restrict who extends the config PCR and bind its measurements to
   completed activations (R4).

D2 Config rollback prevention
   Refuse a config older than the one a target activated, and
   authenticate the selection journal (R14).

D3 The register as a systemd NvPCR
   Register the index as a systemd NvPCR, so that its name follows the
   UKI signing key instead of each boot's PCR values and systemd-aware
   verifiers find it in PCR 9, and measure the anchor through
   ``systemd-pcrextend`` so that systemd's log explains it (R11).

D4 Signed PCR policies
   Signed policies for the kernel and initrd PCRs, so that a verifier
   needs no golden values.

D5 In-kernel detach
   Detach and unpin from the signed unload directive in kernel context,
   which :src:`bpf/unload.c` holds a placeholder for, once ``bpf_sys_bpf()``
   supports it (R1).

D7 Pins without the mount tree
   Keep the enforcement links alive without depending on the bpffs
   mount (R3), tracked in `issue 22
   <https://github.com/shirudo-dev/shirudo/issues/22>`__.

D8 Legacy mount moves
   Check the source of a legacy ``MS_MOVE`` (R3), tracked in `issue 12
   <https://github.com/shirudo-dev/shirudo/issues/12>`__.

D9 Perf events across exec
   Refuse task-bound perf events that a task opened before the exec
   that marks it (T3), tracked in `issue 11
   <https://github.com/shirudo-dev/shirudo/issues/11>`__.

D10 A payload type in the signed message
   Sign the payload type with the loader and the data, so that a
   signature made for a Java upatch verifies for nothing a BPF header
   can describe, and the reverse, without resting on the signed
   sections that follow (T15).

Out of scope
------------

- Compromise of the operator host or of the signing key itself.
- A malicious or faulty kernel, verifier, TPM or hardware, and physical
  attacks (ADV-G).
- Denial of service: removing the binary, cutting the network, filling
  the disk, holding a lock file, stopping a process. shirudo refuses
  rather than fail over, and several such refusals are listed above.
- The correctness or safety of a upatch an authorized signer built.
- Fleet inventory, rollout order, retries, scheduling and consistency
  across targets. shirudo reports one machine.
- Remote access and audit retention, which belong to the infrastructure
  the operator already runs.

.. _tm-duties:

Duties
------

The mechanisms above hold only when the deployer and the verifier do
their part. :doc:`/operate/plan/hardening` and :doc:`/operate/run/attest` are
the procedures.

The deployer:

- Builds the kernel with the signed-loader ABI and the kernel project
  patch set (A3), ``CONFIG_MODULE_SIG`` (A4), ``CONFIG_COMPAT=n`` (A5),
  the TPM driver without ``i2c-dev`` or ``spidev`` on its bus (A8), and
  ``CONFIG_BLK_DEV_WRITE_MOUNTED=n`` (A10); the pre-flight of ``init``
  refuses a kernel without A4
- Boots a signed, measured UKI under Secure Boot whose command line
  carries ``lsm=`` with ``bpf``, ``bpf.keyring_unsealed=1`` and
  ``dm_verity.keyring_unsealed=1``, and whose command line, kernel and
  initrd name no resume device (A6, A9, A11)
- Keeps generic tools off the runtime image (A14)
- Keeps the environment files of the units absent or empty (U3) and
  starts every shirudo unit from the runtime image (U7)
- Uses only ML-DSA-87 certificates from ``shirudo genkey``, repository
  certificates included (U4)
- Treats the TPM owner password as known to root (R20)
- Checks the fingerprint of every certificate it installs (U15)
- Watches the size of the eventlog (U6) and the keepalives, and treats a
  ``tampered`` status as an incident to understand, not a condition to
  retry (:doc:`/operate/troubleshoot/incident-tampered`)

The verifier:

- Uses a fresh, unique ``--nonce`` for each verification
- Records the attestation key name at enrollment after a challenge whose
  endorsement key chains through ``--ek-ca`` or matches ``--ek-name``,
  and passes ``--ak-name`` on every verification (U1, R10)
- Pins the binding with ``--expect-bind-pcr=9=<value>`` and
  ``--expect-bind-pcr=11=<value>`` (U9, R7, R12)
- Gives an expected state: ``--cert`` with ``--upatch`` or ``--expect``
  and ``--tree-root``, or ``--expect-chain`` (U1)
- Gives ``--expect-config-root`` with ``--expect-config-pcr`` (R14)
- Gives ``--strict-anchor`` where nothing else measures into PCR 9
  after ``init`` (R11), and ``--expect-pcr`` for the firmware, kernel and
  initrd values its policy accepts
- Treats ``bound_in``, the eventlog's content beyond the replay,
  ``shirudo status``, the keepalives and the tamper counters as the
  target's own account (R17)

Related
-------

- :doc:`security-model` for the short version
- :doc:`tamper-counters` for every counter and its hooks
- :doc:`cryptography` for every algorithm and where it is used
- :doc:`/internals/enforcement`, :doc:`/internals/seal`,
  :doc:`/internals/signed-loader` and
  :doc:`/internals/measurement-register` for the mechanisms
- :doc:`/concepts/background/bpf-lsm`,
  :doc:`/concepts/background/keyrings`, :doc:`/concepts/background/tpm`
  and :doc:`/concepts/background/dm-verity` for the platform background
