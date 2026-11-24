/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The crypto interface of both profiles, on OpenSSL alone, so every key
 * algorithm the kernel verifies and the hybrid key exchange come from
 * one implementation.
 */

#ifndef SHIRUDO_CRYPTO_H
#define SHIRUDO_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

#include <curl/curl.h>

#include <shirudo/misc.h>

#define CRYPTO_SHA256_LEN 32

struct sha256_ctx {
	void *impl;
};

int sha256_init(struct sha256_ctx *ctx) __must_check;
int sha256_update(struct sha256_ctx *ctx,
		  const void *data, size_t len) __must_check;
int sha256_final(struct sha256_ctx *ctx,
		 __u8 out[CRYPTO_SHA256_LEN]) __must_check;
void sha256_free(struct sha256_ctx *ctx);
/* Where it fails, out is all zeros. */
int sha256_buffer(const void *data, size_t len,
		  __u8 out[CRYPTO_SHA256_LEN]) __must_check;
/*
 * BASE64_LEN() is the length of the base64 of n bytes and BASE64_SIZE()
 * the out_sz base64_encode() needs for them, its terminator included.
 */
#define BASE64_LEN(n)	(4 * (((n) + 2) / 3))
#define BASE64_SIZE(n)	(BASE64_LEN(n) + 1)

int base64_encode(const __u8 *data, size_t len,
		  char *out, size_t out_sz) __must_check;

/* 0 when valid, -EKEYREJECTED when not. */
int ecdsa_p256_verify(const __u8 x[32], const __u8 y[32],
		      const __u8 digest[CRYPTO_SHA256_LEN],
		      const __u8 r[32], const __u8 s[32]) __must_check;

struct cert {
	void *impl;
};

int cert_read_file(const char *path, struct cert *cert) __must_check;
int cert_read_fd(int fd, struct cert *cert) __must_check;
void cert_free(struct cert *cert);
/* SHA-256 of the whole DER certificate; cert_pubkey_digest() of its SPKI. */
int cert_sha256(const struct cert *cert, __u8 out[CRYPTO_SHA256_LEN]) __must_check;
int cert_pubkey_digest(const struct cert *cert,
		       __u8 out[CRYPTO_SHA256_LEN]) __must_check;
/* The provider's name for the cert's public key, e.g. "ML-DSA-87". */
int cert_key_algorithm(const struct cert *cert,
		       char *out, size_t out_sz) __must_check;
/* The subject on one line, "O=Example, CN=fleet", control bytes escaped. */
int cert_subject(const struct cert *cert, char *out, size_t out_sz)
	__must_check;
/* The start of the validity period as a UTC date, YYYY-MM-DD. */
int cert_not_before(const struct cert *cert, char out[11]) __must_check;
int verify_detached(const __u8 *payload, size_t payload_len,
		    const __u8 *signature, size_t signature_len,
		    const struct cert *cert) __must_check;
/*
 * Whether a signer of the CMS blob names this certificate, by key id
 * or by issuer and serial: 1 when one does, 0 when none, -EINVAL when
 * the blob does not parse. Says nothing about the signature's validity.
 */
int cms_signed_by(const __u8 *signature, size_t signature_len,
		  const struct cert *cert) __must_check;

struct tls_ca {
	const char *path;
	void *impl;
};

void tls_ca_cleanup(struct tls_ca *ca);

/*
 * shirudo's TLS policy for every libcurl handle it opens: TLS 1.3 only
 * and hybrid ML-KEM key exchange by default. Exact hosts in
 * tls.classical_hosts may also negotiate classical groups, from the
 * immutable runtime config on targets or root-managed host config on
 * operator commands. This setting does not change certificate
 * verification. ca may be NULL; otherwise it
 * is the extra trust anchor fed to the SSL_CTX callback. Returns 0 or a
 * negative errno; callers must not connect when it fails.
 */
int tls_curl_policy(CURL *curl, struct tls_ca *ca) __must_check;

int hmac_sha256(const __u8 *key, size_t key_len,
		const void *data, size_t len,
		__u8 out[CRYPTO_SHA256_LEN]) __must_check;

/* AES-128 in CFB mode with a zero IV and no padding. */
int aes128_cfb_encrypt(const __u8 key[16], const __u8 *in,
		       size_t len, __u8 *out) __must_check;

/*
 * RSA-OAEP with SHA-256, MGF1-SHA-256 and the given label to the
 * modulus n with the public exponent e (0 for 65537).
 */
int rsa_oaep_encrypt(const __u8 *n, size_t n_len, __u32 e,
		     const void *label, size_t label_len,
		     const __u8 *in, size_t in_len,
		     __u8 *out, size_t cap, size_t *out_len) __must_check;

/*
 * One ephemeral P-256 ECDH against the point (x, y): the ephemeral
 * public point and the shared secret's x coordinate.
 */
int ecdh_p256_ephemeral(const __u8 x[32], const __u8 y[32],
			__u8 eph_x[32], __u8 eph_y[32],
			__u8 z[32]) __must_check;

int base64_decode(const char *in, size_t in_len, __u8 *out,
		  size_t cap, size_t *out_len) __must_check;

int cert_read_der(const __u8 *der, size_t len,
		  struct cert *cert) __must_check;
/* A DER or a PEM certificate, as cert_read_file() takes from a file. */
int cert_read_memory(const __u8 *buf, size_t len,
		     struct cert *cert) __must_check;

struct cert_pubkey {
	bool		rsa;
	__u8		n[512];
	size_t		n_len;
	__u32		e;
	__u8		x[32];
	__u8		y[32];
};

int cert_pubkey(const struct cert *cert,
		struct cert_pubkey *out) __must_check;

/*
 * Chain the certificate to the PEM bundle of trusted issuers at path.
 * -EKEYREJECTED when it does not chain, with *reason set to libcrypto's
 * static explanation; -EINVAL when the bundle cannot be loaded.
 */
int cert_verify_chain(const struct cert *cert,
		      const char *bundle_path, const char **reason)
	__must_check;

/* Log libcrypto's last error under where. */
void openssl_complain(const char *where);

#endif /* SHIRUDO_CRYPTO_H */
