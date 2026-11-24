// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * SHA-256, X.509 and CMS primitives on libcrypto; linked into both profiles.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "io.h"
#include "keys.h"
#include "log.h"
#include "malloc.h"

static int read_x509(const char *path, X509 **out)
{
	int fd = open_trusted(path, O_RDONLY);
	X509 *cert;
	BIO *bio;

	*out = NULL;
	if (fd < 0)
		return fd;
	bio = BIO_new_fd(fd, BIO_CLOSE);
	if (!bio) {
		close(fd);
		return -ENOMEM;
	}
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!cert) {
		ERR_clear_error();
		/* file BIOs report a successful reset as 0, not 1 */
		if (BIO_reset(bio) >= 0)
			cert = d2i_X509_bio(bio, NULL);
	}
	BIO_free(bio);
	if (!cert) {
		ERR_clear_error();
		return -EINVAL;
	}
	*out = cert;
	return 0;
}

int sha256_init(struct sha256_ctx *ctx)
{
	EVP_MD_CTX *md;

	if (!ctx)
		return -EINVAL;
	ctx->impl = NULL;
	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(md);
		return -EIO;
	}
	ctx->impl = md;
	return 0;
}

int sha256_update(struct sha256_ctx *ctx,
		  const void *data, size_t len)
{
	if (!ctx || !ctx->impl || (len && !data))
		return -EINVAL;
	return EVP_DigestUpdate(ctx->impl, data, len) == 1 ? 0 : -EIO;
}

int sha256_final(struct sha256_ctx *ctx,
		 __u8 out[CRYPTO_SHA256_LEN])
{
	__u32 len = 0;
	int ret;

	if (!ctx || !ctx->impl || !out)
		return -EINVAL;
	ret = EVP_DigestFinal_ex(ctx->impl, out, &len) == 1 && len == 32 ? 0 : -EIO;
	EVP_MD_CTX_free(ctx->impl);
	ctx->impl = NULL;
	return ret;
}

void sha256_free(struct sha256_ctx *ctx)
{
	if (!ctx)
		return;
	EVP_MD_CTX_free(ctx->impl);
	ctx->impl = NULL;
}

int sha256_buffer(const void *data, size_t len,
		  __u8 out[CRYPTO_SHA256_LEN])
{
	struct sha256_ctx ctx;
	int ret;

	ret = sha256_init(&ctx);
	if (!ret)
		ret = sha256_update(&ctx, data, len);
	if (!ret)
		ret = sha256_final(&ctx, out);
	else
		sha256_free(&ctx);
	if (ret && out)
		memset(out, 0, CRYPTO_SHA256_LEN);
	return ret;
}

int base64_encode(const __u8 *data, size_t len,
		  char *out, size_t out_sz)
{
	size_t need;

	if (!data || !out || len > INT_MAX)
		return -EINVAL;
	need = BASE64_SIZE(len);
	if (out_sz < need)
		return -EINVAL;
	if (EVP_EncodeBlock((__u8 *)out, data, (int)len) < 0)
		return -EIO;
	out[need - 1] = '\0';
	return 0;
}

static EVP_PKEY *p256_public_key(const __u8 x[32], const __u8 y[32])
{
	EVP_PKEY_CTX *kctx;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM params[3];
	__u8 point[65];

	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);
	params[0] = OSSL_PARAM_construct_utf8_string("group", (char *)"P-256",
						     0);
	params[1] = OSSL_PARAM_construct_octet_string("pub", point,
						      sizeof(point));
	params[2] = OSSL_PARAM_construct_end();
	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!kctx || EVP_PKEY_fromdata_init(kctx) <= 0 ||
	    EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	EVP_PKEY_CTX_free(kctx);
	return pkey;
}

int ecdsa_p256_verify(const __u8 x[32], const __u8 y[32],
		      const __u8 digest[32],
		      const __u8 r[32], const __u8 s[32])
{
	BIGNUM *br = NULL, *bs = NULL;
	EVP_PKEY_CTX *vctx = NULL;
	ECDSA_SIG *sig = NULL;
	EVP_PKEY *pkey = NULL;
	int der_len, ret = -EIO;
	__u8 *der = NULL;

	pkey = p256_public_key(x, y);
	if (!pkey) {
		ret = -EINVAL;
		goto out;
	}
	br = BN_bin2bn(r, 32, NULL);
	bs = BN_bin2bn(s, 32, NULL);
	sig = ECDSA_SIG_new();
	if (!br || !bs || !sig || !ECDSA_SIG_set0(sig, br, bs))
		goto out;
	br = NULL;
	bs = NULL;
	der_len = i2d_ECDSA_SIG(sig, &der);
	if (der_len <= 0)
		goto out;
	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (!vctx || EVP_PKEY_verify_init(vctx) <= 0 ||
	    EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) <= 0)
		goto out;
	ret = EVP_PKEY_verify(vctx, der, (size_t)der_len, digest, 32) == 1 ?
	     0 : -EKEYREJECTED;
out:
	OPENSSL_free(der);
	ECDSA_SIG_free(sig);
	BN_free(br);
	BN_free(bs);
	EVP_PKEY_CTX_free(vctx);
	EVP_PKEY_free(pkey);
	ERR_clear_error();
	return ret;
}

int cert_read_file(const char *path, struct cert *cert)
{
	X509 *x509;
	int ret;

	if (!path || !cert)
		return -EINVAL;
	ret = read_x509(path, &x509);
	cert->impl = x509;
	return ret;
}

int cert_read_fd(int fd, struct cert *cert)
{
	size_t len = 0;
	__u8 *der;
	int ret;

	if (fd < 0 || !cert)
		return -EINVAL;
	ret = read_fd(fd, "certificate", KEYS_DER_MAX, &der, &len);
	if (ret)
		return ret;
	ret = cert_read_der(der, len, cert);
	xfree(der, len + 1);
	return ret;
}

void cert_free(struct cert *cert)
{
	if (!cert)
		return;
	X509_free(cert->impl);
	cert->impl = NULL;
}

int cert_sha256(const struct cert *cert, __u8 out[CRYPTO_SHA256_LEN])
{
	__u32 len = 0;

	if (!cert || !cert->impl || !out)
		return -EINVAL;
	if (X509_digest(cert->impl, EVP_sha256(), out, &len) != 1 ||
	    len != CRYPTO_SHA256_LEN)
		return -EINVAL;
	return 0;
}

/*
 * SHA-256 over the DER SubjectPublicKeyInfo, the bytes Go's
 * x509.MarshalPKIXPublicKey writes; X509_pubkey_digest() hashes only the
 * key's bit string, which is easy to mistake for it. Re-encoding through
 * i2d_X509_PUBKEY keeps the value identical for every key algorithm the
 * X.509 parser accepts, including ML-DSA keys libcrypto cannot otherwise
 * marshal as a bare EVP_PKEY on older releases.
 */
int cert_pubkey_digest(const struct cert *cert,
		       __u8 out[CRYPTO_SHA256_LEN])
{
	__u8 *der = NULL, *p;
	int der_len, encoded_len, ret = -EINVAL;
	const X509_PUBKEY *spki;
	__u32 len = 0;

	if (!cert || !cert->impl || !out)
		return -EINVAL;
	spki = X509_get_X509_PUBKEY(cert->impl);
	if (!spki)
		return -EINVAL;
	der_len = i2d_X509_PUBKEY(spki, NULL);
	if (der_len <= 0)
		return -EINVAL;
	der = xmalloc((size_t)der_len);
	if (!der)
		return -ENOMEM;
	p = der;
	encoded_len = i2d_X509_PUBKEY(spki, &p);
	if (encoded_len != der_len)
		goto out;
	if (!EVP_Digest(der, (size_t)der_len, out, &len,
			EVP_sha256(), NULL) || len != CRYPTO_SHA256_LEN)
		goto out;
	ret = 0;
out:
	xfree(der, (size_t)der_len);
	return ret;
}

int cert_key_algorithm(const struct cert *cert,
		       char *out, size_t out_sz)
{
	const char *name;
	EVP_PKEY *pub;

	if (!cert || !cert->impl || !out || !out_sz)
		return -EINVAL;
	pub = X509_get0_pubkey(cert->impl);
	name = pub ? EVP_PKEY_get0_type_name(pub) : NULL;
	if (!name)
		return -ENOPKG;
	if (strscpy(out, name, out_sz) < 0)
		return -ENAMETOOLONG;
	return 0;
}

int cert_subject(const struct cert *cert, char *out, size_t out_sz)
{
	char *text;
	long len;
	BIO *bio;
	int ret;

	if (!cert || !cert->impl || !out || !out_sz)
		return -EINVAL;
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return -ENOMEM;
	ret = -EINVAL;
	if (X509_NAME_print_ex(bio, X509_get_subject_name(cert->impl), 0,
			       XN_FLAG_ONELINE & ~XN_FLAG_SPC_EQ) < 0)
		goto out;
	len = BIO_get_mem_data(bio, &text);
	ret = -ENAMETOOLONG;
	if (len < 0 || (size_t)len >= out_sz)
		goto out;
	if (len)
		memcpy(out, text, (size_t)len);
	out[len] = '\0';
	ret = 0;
out:
	BIO_free(bio);
	return ret;
}

static int asn1_date(const ASN1_TIME *t, char out[11])
{
	struct tm tm;

	if (!t || !ASN1_TIME_to_tm(t, &tm))
		return -EINVAL;
	return strftime(out, 11, "%Y-%m-%d", &tm) == 10 ? 0 : -EINVAL;
}

int cert_not_before(const struct cert *cert, char out[11])
{
	if (!cert || !cert->impl)
		return -EINVAL;
	return asn1_date(X509_get0_notBefore(cert->impl), out);
}

static CMS_ContentInfo *read_cms(const __u8 *signature, size_t len)
{
	const __u8 *next = signature;
	CMS_ContentInfo *cms;

	if (!signature || !len || len > INT_MAX)
		return NULL;
	cms = d2i_CMS_ContentInfo(NULL, &next, (long)len);
	if (cms && next != signature + len) {
		CMS_ContentInfo_free(cms);
		cms = NULL;
	}
	return cms;
}

/*
 * The algorithm comes from the SignerInfo, so an ML-DSA signature,
 * with signedAttrs and SHA-512 or bare on OpenSSL 4, and an RSA one
 * verify through one call; ML-DSA needs libcrypto >= 3.5.
 */
int verify_detached(const __u8 *payload, size_t payload_len,
		    const __u8 *signature, size_t signature_len,
		    const struct cert *cert)
{
	STACK_OF(X509) *signers = NULL;
	BIO *data = NULL, *out = NULL;
	CMS_ContentInfo *cms = NULL;
	X509_STORE *store = NULL;
	int ret = -EINVAL;

	if (!payload || !signature || !cert || !cert->impl ||
	    payload_len > INT_MAX || signature_len > INT_MAX)
		return -EINVAL;
	data = BIO_new_mem_buf(payload, (int)payload_len);
	out = BIO_new(BIO_s_null());
	store = X509_STORE_new();
	if (!data || !out || !store ||
	    X509_STORE_add_cert(store, cert->impl) != 1 ||
	    X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME) != 1)
		goto done;
	signers = sk_X509_new_null();
	if (!signers || !sk_X509_push(signers, cert->impl))
		goto done;
	cms = read_cms(signature, signature_len);
	if (cms && CMS_verify(cms, signers, store, data, out,
			      CMS_BINARY | CMS_DETACHED | CMS_NOINTERN) == 1)
		ret = 0;
done:
	if (ret)
		ERR_clear_error();
	CMS_ContentInfo_free(cms);
	sk_X509_free(signers);
	X509_STORE_free(store);
	BIO_free(out);
	BIO_free(data);
	return ret;
}

int cms_signed_by(const __u8 *signature, size_t signature_len,
		  const struct cert *cert)
{
	STACK_OF(CMS_SignerInfo) *sis;
	CMS_ContentInfo *cms = NULL;
	int i, ret = -EINVAL;

	if (!signature || !cert || !cert->impl || signature_len > INT_MAX)
		return -EINVAL;
	cms = read_cms(signature, signature_len);
	if (!cms)
		goto done;
	sis = CMS_get0_SignerInfos(cms);
	if (!sis)
		goto done;
	ret = 0;
	for (i = 0; i < sk_CMS_SignerInfo_num(sis) && !ret; i++) {
		if (CMS_SignerInfo_cert_cmp(sk_CMS_SignerInfo_value(sis, i),
					    cert->impl) == 0)
			ret = 1;
	}
done:
	if (ret < 0)
		ERR_clear_error();
	CMS_ContentInfo_free(cms);
	return ret;
}

int hmac_sha256(const __u8 *key, size_t key_len,
		const void *data, size_t len, __u8 out[32])
{
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	size_t outl = 0;
	int ret = -EIO;
	EVP_MAC *mac;

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!mac)
		return -EIO;
	params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA256",
						     0);
	params[1] = OSSL_PARAM_construct_end();
	ctx = EVP_MAC_CTX_new(mac);
	if (ctx && EVP_MAC_init(ctx, key, key_len, params) == 1 &&
	    EVP_MAC_update(ctx, data, len) == 1 &&
	    EVP_MAC_final(ctx, out, &outl, 32) == 1 && outl == 32)
		ret = 0;
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
	return ret;
}

int aes128_cfb_encrypt(const __u8 key[16], const __u8 *in,
		       size_t len, __u8 *out)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int n = 0, fin = 0, ret = -EIO;
	__u8 iv[16] = {};

	if (!ctx || len > INT_MAX)
		goto out;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv) == 1 &&
	    EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
	    EVP_EncryptUpdate(ctx, out, &n, in, (int)len) == 1 &&
	    EVP_EncryptFinal_ex(ctx, out + n, &fin) == 1 &&
	    (size_t)n + (size_t)fin == len)
		ret = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

int rsa_oaep_encrypt(const __u8 *n, size_t n_len, __u32 e,
		     const void *label, size_t label_len,
		     const __u8 *in, size_t in_len,
		     __u8 *out, size_t cap, size_t *out_len)
{
	EVP_PKEY_CTX *kctx = NULL, *ectx = NULL;
	BIGNUM *bn = NULL, *be = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	__u8 *lbl = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = -EIO;

	if (n_len > INT_MAX || label_len > INT_MAX)
		return -EINVAL;
	bn = BN_bin2bn(n, (int)n_len, NULL);
	be = BN_new();
	bld = OSSL_PARAM_BLD_new();
	if (!bn || !be || !bld || !BN_set_word(be, e ? e : 65537) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be))
		goto out;
	params = OSSL_PARAM_BLD_to_param(bld);
	kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!params || !kctx || EVP_PKEY_fromdata_init(kctx) <= 0 ||
	    EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		ret = -EINVAL;
		goto out;
	}
	lbl = OPENSSL_malloc(label_len ? label_len : 1);
	if (!lbl)
		goto out;
	memcpy(lbl, label, label_len);
	ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (!ectx || EVP_PKEY_encrypt_init(ectx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_oaep_md(ectx, EVP_sha256()) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, EVP_sha256()) <= 0 ||
	    EVP_PKEY_CTX_set0_rsa_oaep_label(ectx, lbl, (int)label_len) <= 0)
		goto out;
	lbl = NULL;	/* owned by ectx now */
	*out_len = cap;
	if (EVP_PKEY_encrypt(ectx, out, out_len, in, in_len) <= 0)
		goto out;
	ret = 0;
out:
	OPENSSL_free(lbl);
	EVP_PKEY_CTX_free(ectx);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(pkey);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn);
	BN_free(be);
	return ret;
}

int ecdh_p256_ephemeral(const __u8 x[32], const __u8 y[32],
			__u8 eph_x[32], __u8 eph_y[32],
			__u8 z[32])
{
	EVP_PKEY *eph = NULL, *peer = NULL;
	BIGNUM *bx = NULL, *by = NULL;
	EVP_PKEY_CTX *dctx = NULL;
	size_t zlen = 32;
	int ret = -EIO;

	peer = p256_public_key(x, y);
	if (!peer) {
		ret = -EINVAL;
		goto out;
	}
	eph = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (!eph || !EVP_PKEY_get_bn_param(eph, OSSL_PKEY_PARAM_EC_PUB_X, &bx) ||
	    !EVP_PKEY_get_bn_param(eph, OSSL_PKEY_PARAM_EC_PUB_Y, &by) ||
	    BN_bn2binpad(bx, eph_x, 32) != 32 ||
	    BN_bn2binpad(by, eph_y, 32) != 32)
		goto out;
	dctx = EVP_PKEY_CTX_new_from_pkey(NULL, eph, NULL);
	if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(dctx, peer) <= 0 ||
	    EVP_PKEY_derive(dctx, z, &zlen) <= 0 || zlen != 32)
		goto out;
	ret = 0;
out:
	BN_free(bx);
	BN_free(by);
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(eph);
	EVP_PKEY_free(peer);
	return ret;
}

int base64_decode(const char *in, size_t in_len, __u8 *out,
		  size_t cap, size_t *out_len)
{
	EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
	int n = 0, fin = 0, ret = -EINVAL;

	if (!ctx || in_len > INT_MAX || cap < 3 * DIV_ROUND_UP(in_len, 4))
		goto out;
	EVP_DecodeInit(ctx);
	if (EVP_DecodeUpdate(ctx, out, &n, (const __u8 *)in,
			     (int)in_len) < 0 ||
	    EVP_DecodeFinal(ctx, out + n, &fin) < 0)
		goto out;
	*out_len = (size_t)n + (size_t)fin;
	ret = 0;
out:
	EVP_ENCODE_CTX_free(ctx);
	return ret;
}

int cert_read_der(const __u8 *der, size_t len,
		  struct cert *cert)
{
	const __u8 *p = der;

	if (!der || !cert || len > LONG_MAX)
		return -EINVAL;
	cert->impl = d2i_X509(NULL, &p, (long)len);
	return cert->impl ? 0 : -EINVAL;
}

int cert_read_memory(const __u8 *buf, size_t len, struct cert *cert)
{
	BIO *bio;

	if (!buf || !cert || len > INT_MAX)
		return -EINVAL;
	if (!cert_read_der(buf, len, cert))
		return 0;
	ERR_clear_error();
	bio = BIO_new_mem_buf(buf, (int)len);
	if (!bio)
		return -ENOMEM;
	cert->impl = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!cert->impl) {
		ERR_clear_error();
		return -EINVAL;
	}
	return 0;
}

int cert_pubkey(const struct cert *cert,
		struct cert_pubkey *out)
{
	BIGNUM *a = NULL, *b = NULL;
	char group[32] = "";
	int id, ret = -EINVAL;
	EVP_PKEY *pk;

	memset(out, 0, sizeof(*out));
	pk = cert && cert->impl ? X509_get0_pubkey(cert->impl) : NULL;
	if (!pk)
		return -EINVAL;
	id = EVP_PKEY_get_base_id(pk);
	if (id == EVP_PKEY_RSA) {
		if (!EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &a) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &b) ||
		    BN_num_bytes(a) > (int)sizeof(out->n) || BN_num_bytes(b) > 4)
			goto out;
		out->rsa = true;
		out->n_len = (size_t)BN_bn2bin(a, out->n);
		out->e = (__u32)BN_get_word(b);
		ret = 0;
	} else if (id == EVP_PKEY_EC) {
		if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
						    group, sizeof(group), NULL) ||
		    (strcmp(group, "P-256") && strcmp(group, "prime256v1")) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &a) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &b) ||
		    BN_bn2binpad(a, out->x, 32) != 32 ||
		    BN_bn2binpad(b, out->y, 32) != 32)
			goto out;
		ret = 0;
	} else {
		ret = -EPROTONOSUPPORT;
	}
out:
	BN_free(a);
	BN_free(b);
	return ret;
}

int cert_verify_chain(const struct cert *cert,
		      const char *bundle_path, const char **reason)
{
	X509_STORE_CTX *ctx = NULL;
	X509_STORE *store;
	int ret = -EIO;

	*reason = "";
	if (!cert || !cert->impl || !bundle_path)
		return -EINVAL;
	store = X509_STORE_new();
	if (!store)
		return -ENOMEM;
	if (X509_STORE_load_file(store, bundle_path) != 1) {
		ret = -EINVAL;
		goto out;
	}
	/* An intermediate in the bundle is a trust anchor too. */
	if (X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN) != 1)
		goto out;
	ctx = X509_STORE_CTX_new();
	if (!ctx || X509_STORE_CTX_init(ctx, store, cert->impl, NULL) != 1)
		goto out;
	if (X509_verify_cert(ctx) == 1) {
		ret = 0;
	} else {
		*reason = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
		ret = -EKEYREJECTED;
	}
out:
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return ret;
}

void openssl_complain(const char *where)
{
	char buf[256];

	ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
	pr_err("openssl: %s: %s", where, buf);
}
