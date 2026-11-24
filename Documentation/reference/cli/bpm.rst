..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, upatch authors

shirudo bpm
===========

Install, upgrade and remove signed packages of upatches on a target, and
build and publish them to an OCI registry from the operator host.

Runs on: per subcommand, see the table. Target subcommands run as root
with the runtime binary. Requires: per subcommand. Changes measured state:
``install``, ``upgrade``, ``uninstall`` and ``tree sync`` yes, the others
no.

Usage
-----

.. code-block:: none

   shirudo bpm config register add <source> oci://<registry> [--index-repository <repository>] (--cert <certificate> | --cert=<certificate>)
   shirudo bpm config register list
   shirudo bpm config register (remove | rm) <source>
   shirudo bpm config update --base-package <package> --version <version>
                             [--base-digest sha256:<manifest>]
                             [--file <beefile>]
                             [--rodata-input <name>=<path>]... [--keys-dir <dir>]
   shirudo bpm repo update [<source>]
   shirudo bpm tree sync [--dry-run] [--report <path> | --report=<path>]
   shirudo bpm tree append <package> oci://<registry>/<repository> [<append-options>]
   shirudo bpm tree show oci://<registry>/<repository> (--cert <certificate> | --cert=<certificate>)
                         [--reference <reference> | --reference=<reference>] [--walk]
   shirudo bpm key (add | fingerprint) <certificate | package | oci-reference>
   shirudo bpm key list [--json]
   shirudo bpm pull oci://<registry>/<repository>:<tag>
   shirudo bpm info <package>
   shirudo bpm info upatches <package> [--all]
   shirudo bpm info data <package> <member> [--json]
   shirudo bpm push <package> oci://<registry>/<repository>
                    [--keys-dir <dir> | --index-cert <certificate> --index-key <signing-key>]
                    [--new-index]
   shirudo bpm build [<context>] --version <version> [--file <beefile>]
                     [--keys-dir <dir>] [--vmlinux <vmlinux-h>]
                     [--rodata-input <name>=<path>]...
   shirudo bpm install <source>/<name>[@<version>]
   shirudo bpm install oci://<registry>/<repository>:<tag>
   shirudo bpm upgrade
   shirudo bpm list [--json]
   shirudo bpm uninstall <name>
   shirudo bpm --list-cmds

``<package>`` is a local ``.bee`` file or an ``oci://`` reference.
``<source>`` is the name of a registered repository.

.. list-table::
   :header-rows: 1
   :widths: 26 34 14 26

   * - Subcommand
     - Runs on
     - Lock
     - Measured
   * - ``config register add``, ``remove``
     - host without a config image, refused on targets with one
     - no
     - no
   * - ``config register list``
     - target
     - no
     - no
   * - ``config update``
     - operator host, helper
     - no
     - no
   * - ``repo update``
     - target
     - yes
     - no
   * - ``tree sync``
     - target
     - yes
     - yes
   * - ``tree append``, ``tree show``
     - operator host, helper
     - no
     - no
   * - ``key add``
     - host without a config image, refused on targets with one
     - no
     - no
   * - ``key fingerprint``, ``key list``
     - any host
     - no
     - no
   * - ``pull``, ``info``
     - any host
     - no
     - no
   * - ``push``, ``build``
     - operator host, helper
     - no
     - no
   * - ``install``, ``upgrade``, ``uninstall``
     - target
     - yes
     - yes
   * - ``list``
     - target
     - no
     - no

The lock is ``/var/lib/shirudo/locks/bpm.lock``. A locked subcommand waits
for it. The helper subcommands execute ``shirudo-build`` (see
:doc:`shirudo`). ``shirudo bpm --help`` and ``--list-cmds`` show ``build``
and ``push`` only where the helper resolves. Elsewhere they are unknown
subcommands. ``config update``, ``tree append`` and ``tree show`` always
execute the helper and fail with 127 without it.

Subcommand names after ``bpm`` and ``bpm key`` may be abbreviated (see
:doc:`shirudo`). The words after ``config``, ``repo`` and ``tree`` may
not.

config register
---------------

Repositories are registered per host in
``/etc/shirudo/bpm/registries.d/<source>.conf``. On a target with a config
image, the image's ``etc/shirudo/bpm/registries.d/`` is used instead, and
``add`` and ``remove`` are refused with:

.. code-block:: none

   image mode: change repository definitions and keys in a signed config image, then run `shirudo image update`

- ``add`` checks that the endpoint is ``oci://<host>[:<port>]`` without a
  path, checks ``--index-repository`` and that ``--cert`` is a
  certificate, and refuses any other option. It copies the certificate to
  ``/etc/shirudo/bpm/keys/<source>.der`` and writes the source file.
- ``list`` prints the registered source names, one per line.
- ``remove`` and ``rm`` delete the source file and its certificate.

The key file verifies the signed index of the repository
(:doc:`/reference/formats/bpm-formats`).

config update
-------------

``config update`` builds the next version of a package without
compiling it. For each upatch of the base package that declares
``.rodata`` inputs, it checks that the operator's key signed it, runs
the Beefile's ``update`` command for each input to produce the new
``.rodata`` (``--rodata-input`` replaces an input file), signs the upatch
again and signs a new unload directive for it. The base package must be
signed by the same key and declare ``.rodata`` inputs, and ``--version``
must be a SemVer 2.0.0 version greater than its version. Without ``--file``, the Beefile and the
commands it names come from the base package and run on the operator
host: take base packages only from sources you trust. An ``oci://``
base package needs ``--base-digest``, the manifest digest ``bpm push``
printed when you published it, and the command refuses another
manifest: a tag is the registry's to point at any package your key
signed, an older one included, whose loaders and Beefile the command
would take. ``--base-digest`` with a local base package is refused. The output is
``<name>-<version>.bee`` in the current directory. Options take their
value as the next argument only.

repo update
-----------

``repo update`` fetches each source's configured signed index, or the index
for ``<source>`` alone, verifies it with the source's key file and caches it in
``/var/lib/shirudo/bpm/repos/<source>/index.cache``. A source that fails
does not stop the others, and the exit status is then 1. The last verified
index remains usable while the source name, endpoint, index repository
and signing certificate match. After any of these changes, or on a host
with an older ``index.json`` cache, run ``shirudo bpm repo update <source>``
once before using that source for an indexed install or upgrade.

tree sync
---------

``tree sync`` applies the signed upatch tree that
``etc/shirudo/bpm/upatch-tree.conf`` of the config image, or
``/etc/shirudo/bpm/upatch-tree.conf`` without one, names (``endpoint``
and ``reference``). Without that file it exits with 0 at once, without
reading its options.

#. It fetches the publication and checks its tree ID, generation, parent
   and sequence numbers against the state in
   ``/var/lib/shirudo/bpm/upatch-tree/state.json``.
#. It drops from ``upatch-tree/outcomes`` what a sync that stopped left
   past the recorded ``last_seq`` and refuses a record that does not
   cover it.
#. When the publication is a segment that starts past the recorded
   ``last_seq``, it walks back through the sealed segments by their
   digests to the one ``last_seq`` lies in, and refuses a walk of more
   than 65,536 operations, or 1,048,576 when the node has processed
   none. It then takes the segments oldest first, the publication
   last.
#. It refuses a segment that does not start from the node's
   ``history_root`` at its base, or whose operations up to ``last_seq``
   are not the ones the node processed. It completes an operation a
   sync left in progress and records the segment in ``state.json``.
#. For each new operation whose selector matches the node labels
   (``etc/shirudo/node.labels`` of the config image, or
   ``/etc/shirudo/node.labels``), it fetches and verifies the artifact,
   loads (``add``) or unloads (``delete``) it, extends the register with
   a tree event and records the new projection root. Every new
   operation, matched or not, gets its line in ``outcomes``.
#. It prints a JSON report to standard output, or to ``--report``.

A failure names its phase as :doc:`/reference/failure-categories`
lists them, and the sync applies nothing past it. The walk, its limits
and the time a joining node takes, which grows linearly with the tree,
are in :doc:`/reference/formats/upatch-tree`; both limits are to be
revisited on live clusters.

With ``--dry-run``, it reports which operations would apply and applies
none: it fetches and checks every segment of a walk, but neither
records a segment nor writes a line for a new operation, and reports
the recorded ``last_seq``. It still drops the leftovers in ``outcomes``
and completes an operation left in progress. An ``add`` whose kprobe target
module is not loaded is skipped and recorded as ``skipped: module not
loaded``.

tree append
-----------

``tree append`` publishes the ``[upatches.tree]`` entries of a built
package as the next operations of the signed tree at
``<repository>:<reference>`` and prints ``oci://<registry>/<repository>:<reference>
<digest>``. Its options take the value as the next argument or after
``=``:

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Option
     - Default
     - Description
   * - ``--keys-dir``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - Keys directory.
   * - ``--key``, ``--cert``
     - from the keys directory
     - Signing key and certificate.
   * - ``--previous-cert``
     - the signing certificate
     - Certificate that verifies the existing publication. Use the old
       certificate when the next publication will be signed by a new key.
       It does not change the certificate used to sign the new publication.
   * - ``--tree-id``
     - for a new tree, the package name at ``stable`` and
       ``<package>-<reference>`` at another reference
     - Tree ID. Required to extend an existing tree, and it must be that
       tree's: the registry chooses what the reference holds, so only the
       operator can say which tree the new generation belongs to.
   * - ``--reference``
     - ``stable``
     - Tag of the tree publication.
   * - ``--op``
     - ``add``
     - ``add`` or ``delete``.
   * - ``--segment-ops``
     - ``64``
     - Operations after which a segment is sealed, 1 to 512. Any other
       value is refused with ``bpm tree append: --segment-ops must be 1
       to 512``. It may differ from one append to the next.
   * - ``--package-digest``
     - none
     - ``sha256:`` and 64 lowercase hex digits, the manifest digest of an
       ``oci://`` package, as ``bpm push`` prints it and the repository
       index lists it. Required with an ``oci://`` package and refused
       with a package file.

``<package>`` is a ``.bee`` file, or ``oci://<registry>/<repository>:<tag>``
with ``--package-digest``. The append downloads that package to a file
under ``/tmp``, which it removes when it ends, and refuses it with ``bpm
tree append: <package> serves manifest sha256:<hex>, not <digest>`` when
the tag names another manifest: a registry can point a tag at any package
the key ever signed, an older one included. Either form without the
other is a usage error.

The existing publication must pass the checks ``tree sync`` makes before
it applies anything: the sequence numbers, the ``base`` keys and every
operation's digest. Otherwise the append is refused with ``bpm tree
append: the publication at <repository>:<reference> does not verify``
and nothing is published.

A tree is a chain of segments, each one publication document of at most
512 operations; :doc:`/reference/formats/upatch-tree` has the ``base``
keys that link them. An append never splits its operations
across segments. Before it adds its ``n`` operations to the current
segment, which holds ``c``, it seals that segment when ``c`` is at least
``--segment-ops`` or ``c + n`` exceeds 512, so a segment can hold up to
``n - 1`` operations more than ``--segment-ops``. A package holds at most
128 tree entries, so one append always fits in a segment. Figure 1 shows
both cases.

.. figure:: /images/reference-tree-append.svg
   :alt: Two cases of appending three operations. When the segment
         tagged stable, seq 129 to 150, has room, the new generation
         tagged stable holds seq 129 to 153, names the old generation,
         now untagged, as its parent and keeps segment-2 as its base.
         When the segment holds seq 129 to 192 and is full, its
         manifest is tagged segment-3 unchanged, and the new generation
         tagged stable holds only seq 193 to 195 and names segment-3 as
         both its base and its parent.

   Figure 1. What an append of three operations does to a segment with
   room and to a full one.

Sealing leaves the current manifest and document unchanged and tags the
manifest ``segment-<k>``, where ``k`` counts the sealed segments from 1.
The tag only keeps registry garbage collection from deleting the
segment: a target follows ``<reference>`` and reaches the sealed
segments by digest. The append finds ``k`` by doubling it and then
halving the gap, about 2 log\ :sub:`2` ``k`` manifest requests, never
moves an existing tag, and adds none when the last tag already names the
sealed manifest, left by an append that failed after tagging. The new
segment's ``base.seq`` is the sealed ``head.seq``, and its
``base.history_root`` is the sealed segment's ``base.history_root``, 64
zeros for the first segment, folded over the sealed operations.

The tag is written after every check has passed and just before
``<reference>`` moves, so a refused append leaves no tag.

``tree append`` works out every operation of the package, checks each
as a target will and signs the publication before it uploads anything:
when it refuses, the registry is as it was. An entry no target could
take, one with a control character in its id or in a selector value,
fails with ``bpm tree append: the tree entry of <id> makes an operation
no target takes``.

An ``add`` is refused when an XDP program of the upatch selects a device
class that an XDP program of another upatch in the tree selects, and the
selectors of the two operations do not exclude each other. A device runs
one native XDP program, so the second upatch would fail its load on every
node with such a device and ``tree sync`` would stop there. The message
names both upatches, the sequence number of the earlier operation and the
shared classes, and nothing is published. A Java upatch selects no class.

- Only an ``add`` that no later ``delete`` withdrew counts. A ``delete``
  withdraws it when its selector reaches every node the ``add`` reaches:
  it is empty, or it constrains nothing the ``add`` leaves open and
  allows every value the ``add`` allows.
- Two selectors exclude each other when both name architectures, kernel
  build IDs or kernel release prefixes and have none in common, or when
  both name the same label or kernel option and share no value for it.
  Selectors that name different labels do not: one node can carry both.
- The classes of the earlier upatches are read from their artifacts in
  the registry, so the append fails when one of them cannot be fetched.
  Two upatches of the package being appended are compared as well.
- The earlier upatches are those of every segment back to ``seq`` 1. For
  an ``add`` whose XDP programs select a class, the append fetches each
  sealed segment by its digest, as a target that joins the tree does, and
  checks that it verifies against ``--previous-cert``, that it is the
  segment its successor names, ends where the successor starts and has a
  lower generation, and it passes the checks of the current publication
  above. A segment that fails is refused with ``bpm tree append: the
  sealed segment <digest>, which ends at seq <n>, does not verify``.
  A ``delete`` in any later segment withdraws an ``add`` as one in its
  own segment does. The walk covers at most 1,048,576 operations, the
  limit of a joining target; past it the append is refused with ``bpm
  tree append: a joining node walks back <n> operations, past the limit
  of 1048576, so the XDP device classes of the sealed segments cannot be
  checked``. An ``add`` without XDP classes and a ``delete`` fetch no
  sealed segment.

An ``add`` carries the entry's ``fixes``, a ``delete`` none, and every
earlier operation keeps its own. The append is refused, and nothing is
published, when the existing publication holds a ``fixes`` list
``bpm tree append`` would not write; the message is ``bpm tree append:
the publication at <repository>:<reference> has a fixes list bpm tree
append would not write, so it cannot carry it into the next
generation``.

tree show
---------

``tree show`` fetches the tree publication at ``<repository>:<reference>``
(``reference`` defaults to ``stable``) and verifies it as ``tree sync``
does, against the certificate ``--cert`` names instead of a config
image: each layer against its descriptor, the signature, then the tree
ID, the sequence numbers and each operation's digest. It reads no node
state and writes nothing. It prints one JSON object and a newline:

.. code-block:: none

   {"manifest_digest":"sha256:<hex>","document":<document>}

``manifest_digest`` is the digest of the publication's manifest, and
``document`` the signed document's bytes as published, not emitted
again, so keys a node ignores, such as ``fixes``, appear as signed. The
document may hold newlines; read the output as a JSON value, not as a
line.

With ``--walk``, it prints every segment of the tree that way, one
object and a newline per segment, oldest first: the segment at
``base.seq`` 0 first and the publication ``<reference>`` names last. It
walks back from that publication through the sealed segments by the
``base.segment_manifest_digest`` each names, and checks each one as a
target walking back does: fetched by its digest, verified, of the same
tree, ending at its successor's ``base.seq`` and of a lower generation.
It keeps only their digests and fetches each again, by digest, to print
it, so it fetches every sealed segment twice. A tree never sealed prints
the one object ``tree show`` prints without it. Like a joining target,
it refuses a tree whose current segment starts more than 1,048,576
operations in before it fetches a sealed segment, with ``bpm tree show:
the current segment starts after seq <n>, more than the 1048576
operations a joining node walks`` and ``Argument list too long``. A sealed segment it cannot fetch or that does not check is
refused with ``bpm tree show: the sealed segment <digest>, which ends at
seq <n>, cannot be fetched or does not verify``, then the errno: ``No
such file or directory`` for one the registry no longer holds, and
``Numerical result out of range`` for one that is not the segment before
its successor. Nothing is printed before the whole walk back checks; a
segment that the registry no longer serves, or serves with other bytes,
when it is fetched again stops the output after the segments before it,
with ``bpm tree show: the sealed segment <digest> cannot be fetched
again or changed`` and the errno.

A refusal prints ``bpm tree show: <error>`` with the errno ``tree sync``
reports for the same publication: ``Key was rejected by service`` for a
signature that does not verify under the certificate, a layer that does
not match its digest or an operation digest that does not match its
operation, ``No such file or directory`` for a reference that does not
exist, and ``Invalid argument`` for a document that is not a tree
publication.

key
---

- ``key fingerprint`` prints the SHA-256 fingerprint of a certificate's
  public key (SPKI). The argument is a DER certificate, a ``.bee`` package
  (its ``cert.der``) or an ``oci://`` package reference. The certificate
  is read once, so ``key add`` installs the bytes it fingerprints.
- ``key add`` prints the same fingerprint and installs the certificate in
  ``/var/lib/shirudo/keys/<fingerprint>.der``. When
  ``/var/lib/shirudo/keys/cert.der`` does not exist, it links ``cert.der``
  to the new file, which makes it the host's primary BPF signing
  certificate. When ``cert.der`` exists with another public key, ``add``
  refuses with ``EPERM``. On a target with a config image ``add`` is
  refused.
- ``key list`` prints the fingerprints of the certificates in
  ``/var/lib/shirudo/keys`` under the heading ``Package certificates:``,
  or ``none``. With ``--json`` it prints one object with ``schema`` and
  ``fingerprints``.

``key add`` with an ``oci://`` reference installs the certificate the
registry serves. Run ``key fingerprint`` on the same reference first and
compare the result with a fingerprint you obtained out of band.

pull and info
-------------

``pull`` downloads the package layer of an ``oci://`` reference into a
new file in the current directory and checks its digest against the
manifest. The registry chooses the layer title without a signature, so
the file takes that title only when it is a package name ending in
``.bee``, and is named ``<name>-<tag>.bee`` otherwise. ``pull`` never
replaces a file: when one of that name exists, it fails with ``bpm
pull: File exists``, so remove or rename the old one first.

``info`` prints the ``README.md`` of a package. ``info upatches`` lists
its ``upatches/*.upatch`` members, with ``--all`` also the
``.unload.upatch`` directives. ``info data`` decodes the initial
``.rodata`` of one member through its BTF types, with ``--json`` as JSON.
None of them checks the package signature, so each shows a control
character, and a byte that starts no UTF-8 character, as ``?``: in the
``README.md`` all but tab, line feed and a carriage return before a line
feed, in a member or upatch name all of them. ``info data`` refuses a
``.rodata`` whose BTF names a variable or a type with anything but
printable ASCII, and without ``--json`` also a member or an enumerator,
or spells a type through a function prototype or through a chain of
more than 32 modifiers, pointers and arrays. Without ``--json`` it also
refuses a ``.rodata`` whose types nest more than eight deep, typedefs
and modifiers counted, or whose dump would print more than 1048576
values; with ``--json``, one whose structs and arrays nest more than
eight deep or whose JSON would exceed 8 MiB.

push
----

``push`` publishes a ``.bee`` file to ``oci://<registry>/<repository>``
(no tag) and prints ``oci://<registry>/<repository>:<version>
sha256:<digest>``, the digest of the manifest it pushed. With
``--keys-dir``, or ``--index-cert`` and ``--index-key`` together, it also
adds the package to the registry's signed index
``<namespace>/bpm-index:stable``, signed with that key. The namespace is
derived from the package repository path. Without signing options only the
package is published. ``push`` does not read ``SHIRUDO_KEYS_DIR``. Its
options take the value as the next argument or after ``=``.

``push`` refuses a namespace without an index unless ``--new-index`` is
given, and refuses ``--new-index`` where an index exists. The operator
keeps no state, so a registry that answers that it has no index cannot
be told from one that never had any, and the index signed then would
leave out every package listed before. Pass ``--new-index`` for the first
package of a namespace alone.

build
-----

``build`` builds and signs a package from a Beefile
(:doc:`/reference/formats/beefile`):

- The Beefile is ``--file``, else ``<context>/Beefile``, with
  ``<context>`` defaulting to the current directory.
- The keys directory is ``--keys-dir`` (a leading ``~`` is expanded), else
  ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``.
- ``vmlinux.h`` is ``--vmlinux``, else ``./vmlinux.h`` or
  ``./vendor/linux/vmlinux.h`` in the current directory, else the search
  of :doc:`build` in the Beefile's directory.
- ``--rodata-input <name>=<path>`` replaces a ``.rodata`` input file of
  the Beefile. ``<name>`` is the file's base name up to the first dot
  (``watch`` for ``watch.list``). It is repeatable, once per name.
- ``--version`` is a SemVer 2.0.0 version, such as ``1.2.0`` or
  ``1.2.0-rc.1``.
- Every upatch is compiled in the Beefile's directory and signed.
- The output is ``<name>-<version>.bee`` in the current directory, and
  ``build`` prints its path.

Options take the value as the next argument or after ``=``, except
``--rodata-input``.

install, upgrade, uninstall and list
------------------------------------

``install <source>/<name>[@<version>]`` takes the package from the index
cached by ``repo update``: the given version, else the greatest. ``install
oci://<registry>/<repository>:<tag>`` takes the package directly, with the
tag as its version and the source ``direct``. The manifest is then fetched
by tag and not checked against a digest. ``install`` does nothing when a
package of that name is installed, whatever its version.

For each package ``install`` and ``upgrade``:

#. Check the manifest digest and the package's digest and size against
   the index.
#. Extract the package to
   ``/var/lib/shirudo/bpm/packages/<name>/<version>``.
#. Require the package's ``cert.der`` to hold the same public key as
   ``/var/lib/shirudo/keys/cert.der``.
#. Load each ``upatches/*.upatch`` in name order, as ``upatch load
   --no-precheck`` does, each load measured.
#. Record the package in ``/var/lib/shirudo/bpm/state.json``.

``upgrade`` takes no argument. For every package not installed ``direct``
it installs the greatest version in the cached index when that version is
greater than the installed one: it unloads the old version with its
directives, loads the new one and restores the old one when that fails.
When a registered source needs a refreshed cache, ``upgrade`` names the
refresh command. If its signing certificate cannot be read, ``upgrade``
names the affected source. In either case it continues with the other
packages and exits 1.
``upgrade`` fetches no index itself. ``shirudo-bpm-repo-update.timer`` runs
``repo update`` and then ``upgrade`` at boot and 60 seconds after each
run, so a new version in a registered index reaches every target that
runs the timer.

``uninstall <name>`` applies the package's shipped unload directives in
reverse name order, each measured, removes the package directory and
drops it from the state.

``list`` prints the installed packages under the heading ``Installed
packages:`` as a table with the columns ``NAME``, ``VERSION`` and
``SOURCE``, or ``none``. With ``--json`` it prints one object with
``schema`` and ``packages``, a list of ``name``, ``version`` and
``source``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Success, or ``tree sync`` without a configured tree.
   * - 1
     - Failure, printed as ``bpm <action>: <error>``. Also ``config
       register add`` or ``remove`` and ``key add`` on a target with a
       config image.
   * - 2
     - A usage error, printed as ``bpm <subcommand>: <what is wrong>``:
       an unknown subcommand, action or option, an option given twice, a
       value missing, empty or out of range, or an argument missing or
       one too many.
   * - 127
     - A helper subcommand cannot execute ``shirudo-build``.

Files and environment
---------------------

- ``/etc/shirudo/bpm/registries.d/``, ``/etc/shirudo/bpm/keys/``,
  ``/etc/shirudo/bpm/upatch-tree.conf``, ``/etc/shirudo/node.labels``, or
  the same paths in the config image
- ``/var/lib/shirudo/bpm/``: ``repos/``, ``packages/``, ``staging/``,
  ``state.json`` and ``upatch-tree/``, and
  ``/var/lib/shirudo/locks/bpm.lock``
- Registry access: ``BPM_OCI_USERNAME`` and ``BPM_OCI_PASSWORD``,
  ``BPM_OCI_BEARER_TOKEN``, ``REGISTRY_AUTH_FILE``, ``DOCKER_CONFIG`` and
  ``~/.docker/config.json``, ``BPM_OCI_SCHEME`` (``https`` or ``http``),
  ``BPM_OCI_CA_FILE``. The timer services read them from
  ``/etc/shirudo/bpm/environment``. See :doc:`/reference/environment`

Examples
--------

On the operator host, build a package and publish it with its index
entry:

.. code-block:: console

   operator$ shirudo bpm build ./example-shield --version 1.0.0 --keys-dir ~/shirudo-keys
   operator$ shirudo bpm push ./example-shield-1.0.0.bee oci://quay.io/example/example-shield --keys-dir ~/shirudo-keys

On a target, refresh the indexes and install a pinned version:

.. code-block:: console

   target# shirudo bpm repo update
   target# shirudo bpm install example/example-shield@1.0.0

List the packages of a target without any:

.. code-block:: console

   target# shirudo bpm list
   Installed packages:
     none

Preview a tree sync:

.. code-block:: console

   target# shirudo bpm tree sync --dry-run --report=/tmp/tree.json

Print the tree publication a target would sync, verified with the
operator certificate:

.. code-block:: console

   operator$ shirudo bpm tree show oci://quay.io/example/tree --cert ~/shirudo-keys/cert.der

Print every segment of that tree, oldest first:

.. code-block:: console

   operator$ shirudo bpm tree show oci://quay.io/example/tree --cert ~/shirudo-keys/cert.der --walk

Print the fingerprint of the certificate a package carries:

.. code-block:: console

   operator$ shirudo bpm key fingerprint ./example-shield-1.0.0.bee

Related
-------

- :doc:`/operate/run/deliver-packages`
- :doc:`/upatches/publish/publishing`
- :doc:`/reference/formats/beefile`
- :doc:`/reference/formats/bpm-formats`
- :doc:`/reference/systemd-units`
