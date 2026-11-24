..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Package and index formats
=========================

shirudo publishes packages (``.bee`` files) to an OCI registry and lists
them in a signed repository index. The operator writes them with ``bpm
build`` and ``bpm push`` (see :doc:`/reference/cli/bpm`). The target reads
them with ``bpm repo update``, ``bpm install`` and ``bpm upgrade``. The
Beefile a package is built from is in :doc:`beefile`, the ``.upatch``
files inside in :doc:`upatch-format`, and the upatch tree, which
publishes single upatches of a package, in :doc:`upatch-tree`.

CBMC proves the target's readers of these formats within the bounds
:doc:`/contribute/testing/proof-coverage` lists: the tar headers and
member names, the registry's challenges, tokens, headers and
descriptors, and the package names and versions. Lean 4 proves the
version order total for versions of every length, and that every member
name the archive check takes, of any length, extracts strictly below the
package's directory.

What is signed
--------------

Figure 1 shows the objects of one registry namespace, the packages, the
index and a upatch tree, and which of them are signed and which are
pinned by a digest in a signed one. The table gives each object's
protection.

.. figure:: /images/reference-tree-registry.svg
   :alt: One registry namespace holds a package repository with its
         package manifest and certificate referrer, the bpm-index
         repository whose signed index document pins the package
         manifest and archive by digest, and the tree repository. In the
         tree, the segments tagged segment-1 with seq 1 to 64 and
         segment-2 with seq 65 to 128 and the current one tagged stable
         with seq 129 to 150 each hold a signed document and its
         signature, and each names the one before it by
         base.segment_manifest_digest. The operations pin artifact
         manifests tagged upatch-id-payload16. Superseded generations
         are untagged and may be collected. A node at seq 70 walks back
         from stable to segment-2 by digest and then applies seq 71 to
         128 and 129 to 150, oldest first.

   Figure 1. Which objects of a registry namespace are signed, pinned
   by digest, or neither.

.. list-table::
   :header-rows: 1
   :widths: 24 40 36

   * - Object
     - Protection
     - Checked by
   * - ``.upatch`` file
     - CMS signature, ML-DSA-87, over ``loader_insns || data``.
     - The kernel, at every load and unload.
   * - Repository index document
     - Detached CMS signature over the exact document bytes.
     - ``bpm repo update``, against the repository's key file from the
       configuration. ``bpm push`` also checks the published index against
       ``--index-cert`` before it adds an entry.
   * - Package manifest and ``.bee`` archive
     - Not signed. The signed index pins them by ``manifest_digest``,
       ``package_digest`` and ``package_size``.
     - ``bpm install`` and ``bpm upgrade`` from a repository.
   * - Package installed by ``oci://`` reference
     - Not signed and not pinned. The reference names a tag.
     - Only the per-``.upatch`` signatures and the ``cert.der`` check below.
   * - ``cert.der`` in a package
     - Its public key must equal the public key of the target's
       ``/var/lib/shirudo/keys/cert.der``.
     - ``bpm install`` and ``bpm upgrade``, before any upatch loads.
   * - ``Beefile``, ``README.md``, ``build-environment.json``, files
     - Not signed. Covered by the archive digest when the index pins it.
     - None beyond the archive digest.
   * - Certificate referrer manifest
     - Not signed.
     - Not read by shirudo.

The detached signatures, of an index here and of a tree publication
(:doc:`upatch-tree`), use the same CMS profile as the ``.upatch``
signature: DER ``SignedData``, no encapsulated content, no certificates,
ML-DSA-87, signer named by subject key identifier. The verifier checks it
without a validity-time check: against the repository certificate for
an index, or any active, enrolled BPF signer for a tree publication.

Names
-----

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Name
     - Source
     - Rule
   * - Package name
     - Beefile ``[package] name``
     - Starts with a letter or digit, then ``[A-Za-z0-9._-]``, fewer than
       128 characters.
   * - Package version
     - ``bpm build --version``
     - A SemVer 2.0.0 version such as ``1.2.0``, ``1.2.0-rc.1`` or
       ``1.2.0+build.5``, fewer than 128 characters. The newest version is
       chosen by SemVer 2.0.0 precedence, build metadata ignored. The
       target also accepts other versions of ``[A-Za-z0-9._+-]`` that do
       not start with ``.``, from packages built before this rule: such
       a version is older than every SemVer one, and they order by
       their bytes.
   * - upatch name
     - The source file's basename without ``.bpf.c``, ``.bpf.o`` or ``.o``
     - The Beefile cannot override it. 1 to 255 characters of
       ``[A-Za-z0-9._-]``, each ``.`` counting as two, not starting with
       ``.``.

Package archive
---------------

``bpm build`` writes ``<name>-<version>.bee``, a gzip-compressed ustar
archive with one top-level directory ``<name>-<version>/``. Members carry
uid and gid 0 and mtime 0.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Member
     - Content
   * - ``<name>-<version>/``
     - The top-level directory, mode 0755.
   * - ``Beefile``
     - The Beefile the package was built from.
   * - ``<target>``
     - Each ``[[files]]`` entry at its ``target`` path.
   * - ``upatches/<base>.upatch``
     - Each ``[[upatches]]`` load artifact, at its ``load_target``. The
       default name is the source basename without its extension.
   * - ``upatches/<base>.unload.upatch``
     - The matching unload directive, at its ``unload_target``.
   * - ``README.md``
     - Present when the package directory has one.
   * - ``cert.der``
     - The signing certificate, DER.
   * - ``build-environment.json``
     - Build record, see below.

``Beefile``, ``README.md``, ``cert.der`` and ``build-environment.json`` are
reserved and cannot be ``[[files]]`` or upatch targets.
:doc:`/reference/formats/beefile` describes the Beefile.

On install the target loads every regular file in the archive's
``upatches/`` whose name ends in ``.upatch`` but not in
``.unload.upatch``, in name order. Uninstall
and upgrade apply the package's ``<base>.unload.upatch`` files in reverse
name order, and a rolled back install or upgrade reloads each one's
``<base>.upatch``. A name that starts with ``.`` is neither.

Archive reader rules
~~~~~~~~~~~~~~~~~~~~

The target refuses an archive that breaks any of these:

- Each header is a 512-byte ustar header with a valid checksum, a name
  that is NUL-terminated within its 100 bytes, an empty prefix field and a
  size field of octal digits.
- Every member lies under the one top-level directory. No path is
  absolute or has an empty, ``.`` or ``..`` component, so an archive
  rooted at ``./`` is refused, as the member readers would find nothing
  in it.
- Every member is a regular file or a directory.
- At most 4096 members and 256 MiB of content.
- No regular file appears twice.

build-environment.json
~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Key
     - Value
   * - ``format_version``
     - ``1``.
   * - ``builder``
     - ``"bpm build"``.
   * - ``created_at``
     - UTC time, ``YYYY-MM-DDTHH:MM:SSZ``.
   * - ``package.name``, ``package.version``
     - Package name and version. ``bpm push``, ``bpm tree append`` and
       ``bpm config update`` require both.
   * - ``os``, ``arch``
     - ``uname`` system name and machine of the build host.
   * - ``bpm_version``
     - shirudo version of the builder.
   * - ``shirudo.path``, ``shirudo.version``
     - Path and version of the building binary.
   * - ``shirudo.spki_sha256_fingerprint``
     - SHA-256 of the DER ``SubjectPublicKeyInfo`` of ``cert.der``, hex.
       When present, ``bpm push``, ``bpm tree append`` and
       ``bpm config update`` refuse the package if it differs from
       ``cert.der``.
   * - ``upatches[]``
     - Per upatch: ``source``, ``type``, ``load_target``, ``load_output``,
       ``unload_target``, ``unload_output``, ``upatch_name``,
       ``payload_sha256``.

Package in the registry
~~~~~~~~~~~~~~~~~~~~~~~

``bpm push <package> oci://<registry>/<repository>`` uploads:

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Object
     - Content
   * - Package manifest
     - OCI image manifest, ``schemaVersion`` 2. Config blob
       ``{"mediaType":"application/vnd.shirudo.bpm.config.v1+json"}`` of
       that media type. One layer, the ``.bee`` file, media type
       ``application/vnd.shirudo.bpm.package.v1+gzip``, with an
       ``org.opencontainers.image.title`` annotation of the file name.
       Manifest annotations ``dev.shirudo.bpm.package.name``,
       ``dev.shirudo.bpm.package.version``,
       ``org.opencontainers.image.title`` and
       ``org.opencontainers.image.version``. Tagged with the package
       version after the index update.
   * - Certificate referrer
     - OCI image manifest with ``artifactType``
       ``application/vnd.shirudo.bpm.public-key.v1+der``, the empty config
       ``application/vnd.oci.empty.v1+json``, one ``application/pkix-cert``
       layer holding ``cert.der``, and ``subject`` set to the package
       manifest.
   * - Index entry
     - Added when signing material is given (``--keys-dir``, or
       ``--index-cert`` with ``--index-key``), see below.

The last path component of ``<repository>`` follows the package name rule.

A manifest shirudo reads, for a package, an index, a tree publication or
an artifact, is refused unless each of its layers is an object with a
``mediaType``, a ``sha256:`` digest and a ``size``.

Repository index
----------------

One index per registry namespace, at
``<registry>/<namespace>/bpm-index:stable``.

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Object
     - Content
   * - Index manifest
     - OCI image manifest, ``schemaVersion`` 2, ``artifactType``
       ``application/vnd.shirudo.bpm.index.v1``, the empty config, and
       exactly one document layer and one signature layer.
   * - Document layer
     - The index document, media type
       ``application/vnd.shirudo.bpm.index.v1+json``.
   * - Signature layer
     - Detached CMS signature over the document layer's bytes, media type
       ``application/vnd.shirudo.bpm.index.signature.v1``.

The index document:

.. code-block:: text

   {"schema": 1,
    "generated_at": "<utc-time>",
    "packages": [
      {"name": "<package>", "version": "<version>",
       "repository": "<repository>",
       "manifest_digest": "sha256:<hex>",
       "package_digest": "sha256:<hex>",
       "package_size": <bytes>,
       "signer_fingerprint": "<hex>"}]}

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Key
     - Value
   * - ``schema``
     - ``1``. Required.
   * - ``generated_at``
     - UTC time of the push. Not read by the target.
   * - ``packages``
     - Required. At most 512 entries. ``bpm push`` sorts them by name,
       then version.
   * - ``name``, ``version``
     - Package name and version.
   * - ``repository``
     - Repository path on the index's registry, without the host.
   * - ``manifest_digest``
     - Digest of the package manifest. The target fetches the manifest by
       this digest and refuses other bytes.
   * - ``package_digest``
     - Digest of the ``.bee`` layer. The target refuses a manifest whose
       package layer has another digest, and a download that hashes to
       another value.
   * - ``package_size``
     - Size of the ``.bee`` layer in bytes, required and positive. The
       target refuses a layer of another size.
   * - ``signer_fingerprint``
     - ``shirudo.spki_sha256_fingerprint`` of the package. Not checked by
       the target.

A published version is immutable: ``bpm push`` refuses to list a name and
version again with a different ``manifest_digest`` or ``package_digest``.
The target stores the verified document in
``/var/lib/shirudo/bpm/repos/<source>/index.cache``. Four newline-terminated
lines precede the original document bytes. They hold the source name,
configured endpoint, effective index repository and 64 lowercase hex
digits of the SHA-256 of the signing certificate's DER. A refresh replaces
the whole file in one rename. Indexed installs and upgrades compare all
four fields with the current source before reading the document.

Limits
------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Item
     - Limit
   * - Package file read by ``bpm push``
     - 256 MiB
   * - Archive members
     - 4096 members, 256 MiB of content
   * - Member name
     - fewer than 100 bytes, no ustar prefix
   * - ``build-environment.json`` and ``Beefile`` read by ``bpm push``
       and ``bpm tree append``
     - 4 MiB
   * - Index entries
     - 512
   * - JSON document
     - 8 MiB
   * - Detached signature
     - 64 KiB (writer)

Related
-------

- :doc:`beefile`
- :doc:`upatch-tree`
- :doc:`/upatches/publish/publishing`
- :doc:`/operate/run/deliver-packages`
- :doc:`/reference/cli/bpm`
- :doc:`/reference/configuration` for repository settings
