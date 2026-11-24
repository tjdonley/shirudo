// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <string.h>

#include "crypto.h"
#include "hex.h"
#include "unit.h"

static void sha256_matches_fips_180_vector(void)
{
	static const char want[] =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	char hex[2 * CRYPTO_SHA256_LEN + 1];
	__u8 d[CRYPTO_SHA256_LEN];

	ASSERT_EQ(sha256_buffer("abc", 3, d), 0);
	hex_encode(d, sizeof(d), hex);
	EXPECT_STREQ(hex, want);
}

static void sha256_buffer_zeroes_a_failed_digest(void)
{
	__u8 out[CRYPTO_SHA256_LEN], zero[CRYPTO_SHA256_LEN] = {};

	memset(out, 0xff, sizeof(out));
	EXPECT_NE(sha256_buffer(NULL, 3, out), 0);
	EXPECT_MEMEQ(out, zero, sizeof(out));
}

static void cert_sha256_hashes_the_der_certificate(void)
{
	static const char pem[] =
		"-----BEGIN CERTIFICATE-----\n"
		"MIH+MIGxoAMCAQICAQEwBQYDK2VwMA8xDTALBgNVBAMMBHVuaXQwHhcNMjYxMTI0\n"
		"MTY0NzIwWhcNMjYxMTI1MTY0NzIwWjAPMQ0wCwYDVQQDDAR1bml0MCowBQYDK2Vw\n"
		"AyEAGstShqT1ZoSGQVxHIuc56aDkf1S/jbNLX+6ZayrmyxGjMjAwMB0GA1UdDgQW\n"
		"BBRTfNKkZhU8zRJMJZUJqg798VDqPTAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANB\n"
		"APqxkDRdY5fl+pCP8/V93kipif3xacKpnoxG2xkQflhZVxx3xks2fZnmrp5qBooL\n"
		"sfYxslu6i6cUD87PNNW0XQs=\n"
		"-----END CERTIFICATE-----\n";
	static const char want[] =
		"cc599a9a8988631cacaf820ca3dda624b7772ae634ac771e15c4e593ccee5945";
	struct cert cert __cleanup(cert_free) = {};
	__u8 digest[CRYPTO_SHA256_LEN];
	char hex[2 * sizeof(digest) + 1];

	ASSERT_EQ(cert_read_memory((const __u8 *)pem, sizeof(pem) - 1, &cert), 0);
	ASSERT_EQ(cert_sha256(&cert, digest), 0);
	hex_encode(digest, sizeof(digest), hex);
	EXPECT_STREQ(hex, want);
}

static const struct unit_case cases[] = {
	UNIT_CASE(sha256_matches_fips_180_vector),
	UNIT_CASE(sha256_buffer_zeroes_a_failed_digest),
	UNIT_CASE(cert_sha256_hashes_the_der_certificate),
	{}
};

UNIT_SUITE(crypto_openssl, cases);
