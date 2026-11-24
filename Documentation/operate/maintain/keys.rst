..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Manage signing keys
===================

A target trusts a small set of keys, and each one enters at a different
time. Some are fixed when the target is first provisioned, some change
with a signed config, and some change only with a new runtime image and a
reboot. This page lists the keys, shows what can change when, and walks
through vouching for a signer and revoking one.

Enroll replacement keys before switching signing to them. BPF signers
join the sealed keyring at boot; use ``shirudo image stage`` to select a
config with additional vouched signers for the next planned reboot.
Config verification certificates come from the runtime image.

Before you begin
----------------

- The operator host with the operator package, and the key directories
  you created with ``shirudo genkey``. Each holds ``signing_key.pem``
  (mode ``0600``, the signing helper refuses any other mode) and
  ``cert.der``.
- The source tree of the config image the target runs, as built in
  :doc:`/operate/deploy/boot-integration`.
- Root on the target. On the target, ``shirudo`` is the runtime image's
  binary, as :ref:`runtime-invocation` sets up.

Key inventory
-------------

Figure 1 shows how ``init`` builds the kernel's two keyrings from the
runtime image and the config image, and which key checks what. The
table lists every key.

.. figure:: /images/operate-key-trust.svg
   :alt: The .bpf keyring holds the runtime image's primary certificate
         and the config image's vouched certificates minus its
         revocations; the .dm-verity keyring holds the runtime image's
         config certificates. Tree publications verify against the active,
         non-revoked BPF signers; package indexes use their repository
         certificate.

   Figure 1. The keys a target trusts and the keyrings ``init`` builds
   from them.

.. list-table::
   :header-rows: 1
   :widths: 22 28 50

   * - Key
     - Where the target takes it from
     - What it authorizes
   * - Runtime primary BPF certificate
     - ``keys/cert.der`` in the runtime image, read as
       ``/run/shirudo/runtime/keys/cert.der``
     - Signed loaders of upatches and, while not revoked, upatch tree
       publications.
   * - Vouched BPF certificates
     - ``keys/trusted/<name>.der`` with ``keys/trusted/<name>.vouch`` in
       the config image
     - Signed loaders of upatches and tree publications. A certificate
       joins the set when its
       vouch verifies under a certificate already in the set, starting
       from the runtime primary. The set holds at most 16 certificates.
   * - Revocation records
     - ``keys/revoked/<fingerprint>.der`` in the config image
     - Nothing. Each record removes the certificate it holds from the
       set.
   * - Config verification certificate
     - ``etc/shirudo/config-cert.der`` in the runtime image, named by
       the repeatable ``config.verification_key`` setting
     - Config images. Init enrolls all listed certificates in the
       kernel's ``.dm-verity`` keyring before sealing it. The runtime
       generator numbers additional files ``config-cert-2.der`` and on.
   * - Kernel trusted keys
     - The kernel's built-in trusted keyring, and the secondary and
       platform keyrings when the kernel enables them for dm-verity
     - The kernel's dm-verity signature check also consults these rings.
       Before creating the mapping, shirudo additionally verifies the
       root signature against the runtime's config certificates, so an
       unrelated kernel-trusted key does not authorize a config.
   * - Repository index certificates
     - ``etc/shirudo/bpm/keys/`` in the config image, named by
       ``key_file`` in ``etc/shirudo/bpm/registries.d/``
     - The package index of that repository. shirudo does not require
       ML-DSA-87 for them.
   * - Attestation key (AK) and endorsement key (EK)
     - The TPM. Both are primaries under the endorsement hierarchy with
       fixed templates, so one TPM always yields the same keys.
     - The AK signs the evidence. The EK proves at enrollment that the AK
       sits in the same TPM. You record both names when you enroll the
       target, as :doc:`/operate/run/attest` describes.
   * - NV writer key
     - The TPM. Init creates an RSA-3072 key from a random seed at every
       boot and freezes its public key in the kernel.
     - Extensions of the measurement register. The init record carries
       its public key as ``nv_writer_public``.

The BPF signing keys and the config signing key are ML-DSA-87 keys from
``shirudo genkey``. The config signing key may be one of the BPF signing
keys or a separate key. Keep the private signing keys on the operator
host. A target needs none, and ``shirudo status --show-full`` on a
target reports ``keys/signing_key.pem absent``.

What can change when
--------------------

.. list-table::
   :header-rows: 1
   :widths: 22 22 26 30

   * - Key
     - First provisioning
     - Signed config (``image update``)
     - New runtime image, UKI and reboot
   * - Runtime primary BPF certificate
     - Set by the runtime image.
     - Cannot change it. The config can revoke it.
     - Changes it. Every certificate in the selected config's
       ``keys/trusted`` must chain from the new primary, or init fails
       before enforcement starts. Every archived upatch must be signed
       by a key in the new set, or the boot restore fails.
   * - Vouched BPF certificates
     - Enrolled from the initial config.
     - Live activation refuses a certificate that is not in the
       ``.bpf`` keyring. Stage that config for the next boot instead.
     - Init verifies a staged config and enrolls its vouched signers
       before sealing the keyring.
   * - Revocation records
     - Applied at boot.
     - Applied at activation.
     - Kept, as part of the selected config.
   * - Config verification certificate
     - Set by the runtime image.
     - Cannot change it.
     - Use a runtime containing both old and new certificates, activate a
       config signed by the new key, then use a runtime containing only
       that key. A selected config signed by no listed key is refused.
   * - Repository index certificates
     - From the initial config.
     - Change at activation. Indexed installs and upgrades from the
       repository then wait for a ``bpm repo update`` that verifies an
       index signed by the new key.
     - Kept, as part of the selected config.
   * - AK and EK
     - Fixed by the TPM.
     - No change.
     - No change. A different TPM needs a new enrollment.
   * - NV writer key
     - Created at boot.
     - No change.
     - A new key at every boot.

The first provisioning is the first boot with enforcement. Init has no
activation record yet and selects the config that ``config.image`` in the
runtime bootstrap file names. From then on the activation record selects
the config, and changing ``config.image`` has no effect.

Check what a target trusts
--------------------------

1. Show the certificates, the trusted set and both keyrings:

   .. code-block:: console

      target# shirudo keys
      Certificate (/run/shirudo/runtime/keys/cert.der):
        Subject:               /CN=shirudo
        Issuer:                /CN=shirudo  (self-signed)
        Public key:            ML-DSA-87
        Fingerprint:           SHA256:c00c2d9a30c11dd98bb53200ac79c744b063a50489e5780968ea97bcb5745eb1
        SPKI fingerprint:      SHA256:6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858
        Issued:                2026-11-03T14:52:11Z

      Signing key (/run/shirudo/runtime/keys/signing_key.pem):
        Present:               no, a target holds no private key

      Trusted set (2 members, 0 revoked, 0 unvouched):
        a8be2bb837b0f052f7652f9edf446594a5465eed614d939964ddfcc96e61ba7f
          sha256 79b04130628135a03630a0ed9e92a574f8701847404ec281469348a09b9b3b45
          vouched by 6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858
        6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858  (primary)
          sha256 c00c2d9a30c11dd98bb53200ac79c744b063a50489e5780968ea97bcb5745eb1

      Keyring (.bpf):
        Serial:                272801410
        Frozen serial:         272801410  (matches)
        Members (2):
          serial=465853497   type=asymmetric  shirudo: 30dee65057025367c4c384928bcf1e4cd8fe0265  (frozen)
          serial=91435879    type=asymmetric  shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e  (frozen)

      Keyring (.dm-verity):
        Serial:                799624487
        Frozen serial:         799624487  (matches)
        Members (1):
          serial=403194297   type=asymmetric  shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e  (frozen)

   ``Certificate`` is the runtime primary. The trusted set lists each
   member by its SPKI fingerprint, with the SHA-256 of its DER and the
   member that vouched for it. ``Keyring (.bpf)`` is what the kernel
   verifies signed loaders against: the serial init froze, and one key
   per member. ``Keyring (.dm-verity)`` holds the configured certificates
   for config roots. ``(frozen)`` marks a member ``init``
   recorded; a member marked ``(not frozen)`` is trusted by the kernel
   all the same, and ``shirudo status`` reports the target ``tampered``.

2. Read the same set from the status report, each certificate with the
   key that holds it. The report folds the keyring sections while
   ``KeyringSealed`` is ``OK``, so ask for them:

   .. code-block:: console

      target# shirudo status --show-full
      ...
      Keyring (.bpf):
        Serial:                272801410
        Frozen serial:         272801410  (matches)
        Certificates:          2 trusted, 0 revoked, 0 unvouched, 2 in the bpf keyring
          a8be2bb837b0f052f7652f9edf446594a5465eed614d939964ddfcc96e61ba7f
            CN=shirudo, ML-DSA-87, issued 2026-11-03
            key 465853497  shirudo: 30dee65057025367c4c384928bcf1e4cd8fe0265  (frozen)
          6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858  (primary)
            CN=shirudo, ML-DSA-87, issued 2026-11-03
            key 91435879  shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e  (frozen)
      ...

   ``unvouched`` counts certificates under ``keys/trusted`` without a
   valid vouch. A config with one is refused, so it stays 0 on a target
   that runs a config.

Vouch for a standby signer
--------------------------

A standby signer is a second BPF signing key that the initial config
enrolls, so that you can revoke the primary later and keep signing
upatches and tree publications. Include it in the first config or stage
that config on an existing target and reboot when appropriate.

1. Create the standby key in a directory of its own:

   .. code-block:: console

      operator$ shirudo genkey --keys-dir=<standby-keys-dir>

2. Sign a vouch for its certificate with the primary key:

   .. code-block:: console

      operator$ shirudo keys vouch <standby-keys-dir>/cert.der \
          -o standby.vouch --keys-dir=<primary-keys-dir>

   The command prints the fingerprint of the certificate it vouched for.
   It refuses to vouch for the signing key's own certificate.

3. Put the certificate and the vouch into the config source tree under
   one name:

   .. code-block:: console

      operator$ mkdir -p config-root/keys/trusted
      operator$ cp <standby-keys-dir>/cert.der \
          config-root/keys/trusted/<standby-fingerprint>.der
      operator$ cp standby.vouch \
          config-root/keys/trusted/<standby-fingerprint>.vouch

   ``<standby-fingerprint>`` is the fingerprint that step 2 printed. Init
   pairs ``<name>.der`` with ``<name>.vouch`` by name. It refuses the whole
   config when a certificate under ``keys/trusted`` has no vouch that
   verifies.

4. Build and sign the config as
   :doc:`/operate/deploy/boot-integration` describes. For a new target,
   use it as the initial config. For an existing target, stage it:

   .. code-block:: console

      target# shirudo image stage <prefix>
      target# shirudo image status

   Staging verifies the image and vouches but does not enroll the new
   signer, activate the config or extend the TPM. The next planned boot
   selects and verifies it before enrolling keys. Cancel a staged
   selection with ``shirudo image stage --cancel``.

5. After the planned reboot, check that ``shirudo keys`` on the target lists
   the standby signer in the trusted set and the ``.bpf`` keyring.

Once both signers are enrolled, switch signing to the standby key.
For the first tree publication signed by it, verify the previous
publication with the old certificate:

.. code-block:: console

   operator$ shirudo bpm tree append <package> oci://<registry>/<tree> \
       --tree-id <tree-id> --keys-dir <standby-keys-dir> \
       --previous-cert <primary-keys-dir>/cert.der

The new publication is signed by the standby key. Later appends use that
key for both checks and can omit ``--previous-cert``. Targets accept
either enrolled signer during the overlap. Replace upatches signed by the
old key before activating a config that revokes it.

On a target, ``shirudo keys add`` and ``shirudo bpm key add`` refuse to
change the trusted set, and ``shirudo keys revoke`` always refuses. The
signed config is the only way in.

Revoke a signer
---------------

Revocation goes through a signed config. Activation removes the key
from the kernel at once.

1. Print the fingerprint of the certificate to revoke:

   .. code-block:: console

      operator$ shirudo bpm key fingerprint <revoked-cert.der>

   The command prints the 64-character SPKI fingerprint, the same value
   that ``shirudo keys`` prints.

2. Add a revocation record to the config source tree:

   .. code-block:: console

      operator$ mkdir -p config-root/keys/revoked
      operator$ cp <revoked-cert.der> config-root/keys/revoked/<fingerprint>.der

   The file name must be the lowercase fingerprint with ``.der``, and the
   file must hold that certificate. Init and ``image update`` refuse any
   other entry under ``keys/revoked``.

3. Build and sign the config under a new prefix, and check it offline:

   .. code-block:: console

      operator$ shirudo-gen-image --source config-root --output revoke-1 \
          --keys-dir <config-keys-dir> --kind config
      operator$ shirudo image verify revoke-1 --cert <config-keys-dir>/cert.der

4. Copy ``revoke-1.img``, ``revoke-1.verity``, ``revoke-1.roothash`` and
   ``revoke-1.p7s`` to the target.

5. Activate the config on the target:

   .. code-block:: console

      target# shirudo image update <path>/revoke-1

   ``<path>`` is where you copied the files. ``image update`` also takes
   an ``https://`` prefix. It prints nothing on success.

6. Check the result:

   .. code-block:: console

      target# shirudo keys
      target# shirudo status --include-eventlog

   The trusted set no longer lists the key, the revoked count went up, and
   the eventlog shows a ``key_revoke`` record followed by an
   ``upatch_unload`` record for each loaded upatch the key signed.

Leaving a certificate out of a config does not revoke it: its key stays
in the ``.bpf`` keyring until the next boot. Revoke it with a record.

``image update`` validates the whole config before it measures anything.
It refuses a config whose set would be empty after the revocation, a
certificate under ``keys/trusted`` without a valid vouch, and a member
that is not in the ``.bpf`` keyring. A refused config changes nothing.

What a revocation does
~~~~~~~~~~~~~~~~~~~~~~

At activation, in this order:

1. shirudo records an ``UPDATE`` event for the config in the config PCR.
2. When the revoked key is in the ``.bpf`` keyring, shirudo unlinks it,
   extends the measurement register with a ``key_revoke`` event and
   appends the record to the eventlog.
3. For every archived upatch the revoked key signed, shirudo unloads it
   when it is loaded, with a measured ``upatch_unload`` event whose
   reason is ``key_revoke``, and removes it from the archive. An archived
   upatch that is not loaded is removed without an event.

At a later boot with the same config, the revocation is not a separate
event. Init enrolls the runtime primary in any case, because the boot
needs it until the config is active, and unlinks it again when the
config revokes it. It removes the archived upatches the revoked keys
signed before it restores the archive. The init event covers the set
after revocation, so ``shirudo attest predict`` takes the remaining
certificates only. :doc:`/operate/run/attest` shows how to predict the
register, and ``--event=revoke:<label>=<cert-sha256>`` adds a revocation
made after boot.

Rotate a config signing key
----------------------------

Use an overlap period so the selected config remains verifiable while
signing changes from C to D.

1. Create D on the operator and build a runtime with both certificates:

   .. code-block:: console

      operator$ shirudo genkey --keys-dir <config-D>
      operator$ shirudo-gen-runtime --binary <target-binary> \
          --bootstrap-conf runtime.conf --cert <bpf-cert> \
          --config-cert <config-C>/cert.der \
          --config-cert <config-D>/cert.der \
          --keys-dir <config-C> --output runtime-CD

   The repeated option puts both config certificates on the runtime
   image and lists them in its bootstrap settings. Init enrolls both
   before sealing ``.dm-verity``.

2. Deploy the runtime and a UKI naming its root hash as
   :doc:`upgrade` describes, then reboot when appropriate. The selected
   C-signed config still verifies.

3. Build a config with D and activate it:

   .. code-block:: console

      operator$ shirudo-gen-image --source <config-root> --output config-D \
          --keys-dir <config-D> --kind config
      target# shirudo image update <path>/config-D

   Build a fresh image with a new root hash, not just a new signature over
   an old cached image. The cache keeps the signature already stored for
   a root. Verify ``shirudo image status`` and ``shirudo keys`` before
   retiring C.

4. Build and deploy another runtime and UKI with only D's certificate.
   After the planned reboot the selected D-signed config verifies, and
   C is no longer in the config keyring.

No target command enrolls a config certificate or removes one live.
Signatures by either enrolled key work during the overlap; two
signatures on one image are not required.

Limits
------

- A live config activation cannot enroll a BPF key. Stage the config
  and reboot instead.
- A config certificate changes only with the authenticated runtime image
  and a reboot. Removing the old key before changing the selected
  config makes init refuse that config.
- Revoking a BPF signer purges upatches it signed. Plan their replacement
  before retiring the signer.
- Vouches are historical authorizations. Revoking A does not
  automatically revoke B merely because A vouched for it. After a
  compromise, the config signer must explicitly revoke any certificate
  whose authorization is no longer trusted.
- A certificate's validity dates do not end its trust. shirudo verifies
  vouches and index and tree signatures without checking them.
- Older signed configs can still be selected. Local rollback prevention
  is not provided; a verifier must check the approved config root and
  boot measurements. See :doc:`/security/threat-model`.


Next steps
----------

- :doc:`/operate/run/attest` to enroll a target and verify evidence
- :doc:`/operate/run/deliver-packages` for repositories and their keys
- :doc:`/reference/cli/keys` and :doc:`/reference/cli/image` for the
  command options
- :doc:`/security/cryptography` for the algorithms
