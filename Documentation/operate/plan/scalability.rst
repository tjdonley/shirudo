..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Scalability
===========

How the pull from OCI registries grows with the number of targets, and
where shirudo and the kernel limit what one target and one upatch can
hold. shirudo's limits come from its code. Kernel limits come from the
kernel source and can differ between kernel versions and architectures;
each one names its constant so that you can look it up in your kernel.
:doc:`/operate/plan/overhead` describes what one target uses.

Fleet
-----

shirudo keeps no fleet state and has no push channel. Every target runs
its own timers and pulls from the registries its config image names, so
the load on a registry grows with the number of targets that follow it.

Registry requests
~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Command
     - Requests per target
   * - ``bpm repo update``
     - Every minute, for every repository: the index manifest, the index
       and its signature, each downloaded in full. There is no
       conditional request, and the cached index is not consulted.
   * - ``bpm tree sync``
     - Every minute with a tree configured: the tree's manifest, payload
       and signature, in full. A target that is behind the segment the
       reference names also fetches each sealed segment back to the one
       its last applied operation lies in, twice: once on the walk back,
       once to apply it. A upatch the tree adds is fetched once,
       manifest and blob, and cached by its layer digest.
   * - ``bpm upgrade``
     - Nothing until the cached index lists a newer version of an
       installed package. Then the package manifest and the whole
       package archive.

A registry that challenges for a bearer token gets three requests for
each of these: the request without credentials, the token request and
the request again with the token. Tokens are not kept between requests
or runs. Every request opens a new connection with its own TLS 1.3
handshake.

N targets that follow R repositories and a tree therefore send a registry
about N × (3R + 3) requests per minute, three times that with token
authentication, and download the indexes, the tree payload and their
signatures N times a minute. An index holds at most 512 entries and has
to parse within 8 MiB.

Timing and failures
~~~~~~~~~~~~~~~~~~~

- ``shirudo-bpm-repo-update.timer`` starts the update at boot and 60
  seconds after each run ends. ``shirudo-bpm-tree-sync.timer`` starts
  the sync 60 seconds after boot and every 60 seconds after that.
  Neither timer sets a random delay, so targets spread over the minute
  only as far as their boot times and run times differ. Targets that
  boot together, after a power cut for example, poll together.
- A version pushed to an index reaches every target that follows the
  repository within about a minute, and every target that has the
  package installed downloads the whole archive, up to 256 MiB, in that
  minute. There is no delta and no resumed download.
- A failed request is not retried. A failed run waits for the next run of
  its timer, and status 429 and ``Retry-After`` get no special handling.
  One unreachable repository does not stop the update of the others,
  and ``bpm upgrade`` still runs from cached indexes that match their
  current repository settings and signing certificates.
- A connection has 30 seconds to open, and a transfer that moves less
  than 1 byte per second for 60 seconds is cut. A request has no overall
  time limit; the service has 30 minutes.

Staged rollouts
~~~~~~~~~~~~~~~

- A repository is one registry endpoint, ``oci://<host>[:<port>]`` without
  a path, and its index is at ``<namespace>/bpm-index:stable`` on it.
  There is no mirror or fallback list. To stage a package, publish it to
  a registry that only canary targets follow before the one the fleet
  follows. Targets reach different registries, or a pull-through cache,
  only when their config images name them.
- The upatch tree is the only source with selectors: kernel release,
  kernel build ID, architecture, kernel configuration and node labels.
  Its reference can be a tag other than ``stable``. A target moves past
  an operation that does not select it for good, so labels changed later
  do not apply operations it skipped before.
- A tree publication, a segment, holds at most 512 operations.
  ``bpm tree append`` seals the segment when it holds ``--segment-ops``
  operations, 64 by default, or when the new ones would not fit, and
  starts one that names it by digest. A target that is behind fetches
  the sealed segments back to its position, up to the walk limit of
  :ref:`upatch-tree-limits`.

:doc:`/operate/run/deliver-packages` sets up repositories and the tree.

Collectors
~~~~~~~~~~

With an endpoint configured, every target sends one keepalive a minute
after the previous one ends, and one request per map of every loaded
upatch 5 seconds after the previous export ends, about 12 a minute. A
collector serves N targets with M exported maps each about
N × (12 × M + 1) requests a minute. A request
waits 10 seconds by default and is retried 3 times. See
:doc:`/operate/run/telemetry`.

One target
----------

shirudo sets no limit on the number of upatches a target loads. The limits
below decide how far one target goes.

shirudo limits
~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 24 38 38

   * - Item
     - Limit
     - When it is reached
   * - Boot restore
     - The init record of a boot grows with the restored set: about
       1.9 KiB, plus 95 bytes and the name for every restored upatch, in
       a buffer sized for the set.
     - The eventlog limits apply, see the next row.
   * - Eventlog
     - Readers accept at most 8 MiB, across all boots, and the log is never
       rotated. A load or an unload adds about 330 bytes plus the name,
       and every boot adds its init record. 100 upatches with 20-character
       names fill 8 MiB in about 600 boots.
     - A load is undone as unmeasured (``tpm_error``), ``init`` stops,
       and status, replay and attestation fail. With
       ``eventlog.max_bytes`` set, loads, unloads and ``init`` refuse
       ``eventlog_full`` first. See U6 in the
       :doc:`/security/threat-model`.
   * - ``upatch list --json``
     - 64 KiB, 162 bytes plus the name per upatch: about 360 upatches with
       20-character names.
     - ``upatch list: json encode failed``, exit status 1. The text
       listing has no limit.
   * - ``shirudo status --json``
     - 8 MiB
     - ``status: json encode failed``
   * - Installed packages
     - 256, and at most 128 upatches per package
     - ``bpm install`` refuses a 257th package. A package with more
       upatches fails to install or upgrade.
   * - BPF signers
     - 16, the runtime primary and the certificates the config vouches
       for
     - ``image stage``, ``image update`` and ``init`` refuse a config
       image whose signer set exceeds it.
   * - Node labels
     - 64, with keys and values shorter than 256 bytes
     - ``bpm tree sync`` stops at the first operation that selects on
       labels.

Kernel limits
~~~~~~~~~~~~~

The kernel sets no limit on the number of BPF programs, maps or links
and charges their memory to the memory cgroup of the loading process,
unless it boots with ``cgroup.memory=nobpf``.
The JIT memory limit, ``net.core.bpf_jit_limit``, refuses only callers
without ``CAP_BPF``. What bounds a target is the attach point.

.. list-table::
   :header-rows: 1
   :widths: 22 50 28

   * - Attach kind
     - Limit
     - Constant
   * - ``fentry``, ``fexit``, ``fmod_ret``, ``lsm``
     - As many programs per kernel function as fit its trampoline image
       of 4 KB, all four kinds together. On x86-64 that is 57 ``fentry``
       or ``fexit`` programs or about 35 ``fmod_ret`` or ``lsm``
       programs, on arm64 about 33 of the latter. The attach of one
       more fails with ``E2BIG``. An ``lsm`` program counts on the
       hook's ``bpf_lsm_<hook>`` function, which shirudo's own programs
       share.
     - ``BPF_TRAMP_IMAGE_MAX_SIZE`` in ``include/linux/bpf.h``
   * - ``tp_btf``
     - No limit per tracepoint
     -
   * - ``kprobe``, ``kretprobe``, ``uprobe``, ``uretprobe``
     - No limit per site; every attachment is a perf event of its own
     -
   * - ``uprobe.multi``, ``uretprobe.multi``
     - 1,048,576 offsets per link, which shirudo also enforces
     - ``MAX_UPROBE_MULTI_CNT`` in ``kernel/trace/bpf_trace.c``
   * - ``cgroup_skb``
     - 64 programs per direction on ``/sys/fs/cgroup``, shared with any
       other software that attaches there
     - ``BPF_CGROUP_MAX_PROGS`` in ``kernel/bpf/cgroup.c``
   * - ``netfilter``
     - One program. shirudo attaches every ``netfilter`` program at
       ``NF_IP6_PRI_RAW_BEFORE_DEFRAG`` on IPv6 pre-routing, and the kernel
       refuses a second BPF hook at the same priority with ``EBUSY``.
     - ``nf_hook_entries_grow()`` in ``net/netfilter/core.c``

shirudo's 48 guards are BPF LSM programs on 39 hooks. Nine hooks carry
two of them: ``bprm_check_security``, ``file_open``, ``inode_link``,
``inode_mkdir``, ``inode_removexattr``, ``inode_rename``,
``inode_setxattr``, ``inode_symlink`` and ``inode_unlink``. On x86-64 an
``lsm`` upatch therefore has 34 places left on those hooks, 35 on the other
30 hooks shirudo uses and 36 on every other hook. shirudo does not count
them: a load that finds the attach point full fails at ``link_create``
with the kernel's ``E2BIG``, or ``EBUSY`` for ``netfilter``, in category
``unknown``.

One upatch
----------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Item
     - Limit
   * - ``.upatch`` file
     - 16 MiB. :doc:`/reference/formats/upatch-format` lists the limit of
       every field.
   * - Signature
     - 64 KiB in the kernel, ``BPF_PROG_MAX_SIGNATURE_SIZE``.
       ``shirudo build`` writes at most 16 KiB.
   * - Signed loader
     - Its instructions and the value of its metadata map together less
       than 16 MiB, the size of the buffer the kernel verifies
       (``DYNPTR_MAX_SIZE``). At most 1,000,000 instructions
       (``BPF_COMPLEXITY_LIMIT_INSNS``).
   * - Each program
     - The verifier processes at most 1,000,000 instructions and allows
       64 maps (``MAX_USED_MAPS``), 256 subprograms (``BPF_MAX_SUBPROGS``)
       and one arena.
   * - Arena
     - 4 GiB (``kernel/bpf/arena.c``)
   * - Name
     - 255 characters from ``A-Z``, ``a-z``, ``0-9``, ``.``, ``_`` and
       ``-``, each ``.`` counting as two, not starting with ``.``.
   * - Map export
     - :doc:`/upatches/write/maps-arenas-serializers` and
       :doc:`/upatches/write/decoders` give the serializer and decoder limits.
   * - Package
     - 128 upatches, 4096 archive entries and 256 MiB

Related
-------

- :doc:`/operate/plan/overhead`
- :doc:`/operate/run/deliver-packages`
- :doc:`/upatches/write/attach-kinds`
- :doc:`/security/threat-model`
