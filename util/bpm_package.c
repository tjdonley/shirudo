// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .bee archive reading, package identity, signed index and tree fetch.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "bpm_oci.h"
#include "bpm_package.h"
#include "bpm_tree.h"
#include "crypto.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "keys.h"
#include "log.h"
#include "malloc.h"
#include "seal.h"

struct index_sink {
	struct bpm_index_entry *items;
	int n;
	struct bpm_index_entry scratch;
};

static int on_index_entry(void *ud)
{
	struct index_sink *s = ud;

	if (s->n >= BPM_MAX_ENTRIES)
		return -E2BIG;
	if (!bpm_name_ok(s->scratch.name) || !bpm_version_ok(s->scratch.version) ||
	    !s->scratch.repository[0] || !s->scratch.manifest_digest[0] ||
	    !s->scratch.package_digest[0] || s->scratch.package_size <= 0)
		return -EINVAL;
	s->items[s->n++] = s->scratch;
	/* A field the next entry leaves out is not this entry's. */
	memset(&s->scratch, 0, sizeof(s->scratch));
	s->scratch.package_size = -1;
	return 0;
}

int bpm_index_parse(const __u8 *body, size_t len,
		    struct bpm_index_entry *entries, int *n_entries)
{
	struct index_sink sink = { .items = entries };
	struct json_array arr = { on_index_entry, &sink };
	struct json_field sub[7], root[2];
	__s64 schema = 0;

	/* Missing from the first entry as from any other, not 0. */
	sink.scratch.package_size = -1;
	memset(sub, 0, sizeof(sub));
	sub[0] = (struct json_field){
		.key = "name", .type = JSON_T_STRING,
		.dst = sink.scratch.name, .dst_cap = sizeof(sink.scratch.name),
	};
	sub[1] = (struct json_field){
		.key = "version", .type = JSON_T_STRING,
		.dst = sink.scratch.version,
		.dst_cap = sizeof(sink.scratch.version),
	};
	sub[2] = (struct json_field){
		.key = "repository", .type = JSON_T_STRING,
		.dst = sink.scratch.repository,
		.dst_cap = sizeof(sink.scratch.repository),
	};
	sub[3] = (struct json_field){
		.key = "manifest_digest", .type = JSON_T_STRING,
		.dst = sink.scratch.manifest_digest,
		.dst_cap = sizeof(sink.scratch.manifest_digest),
	};
	sub[4] = (struct json_field){
		.key = "package_digest", .type = JSON_T_STRING,
		.dst = sink.scratch.package_digest,
		.dst_cap = sizeof(sink.scratch.package_digest),
	};
	sub[5] = (struct json_field){
		.key = "signer_fingerprint", .type = JSON_T_STRING,
		.dst = sink.scratch.signer,
		.dst_cap = sizeof(sink.scratch.signer),
	};
	sub[6] = (struct json_field){
		.key = "package_size", .type = JSON_T_INT,
		.dst = &sink.scratch.package_size,
	};
	root[0] = (struct json_field){
		.key = "schema", .type = JSON_T_INT, .dst = &schema,
	};
	root[1] = (struct json_field){
		.key = "packages", .type = JSON_T_ARRAY,
		.dst = &arr, .sub = sub, .n_sub = ARRAY_SIZE(sub),
	};
	if (json_parse((const char *)body, len, root, ARRAY_SIZE(root)) ||
	    schema != 1 || !root[1].seen)
		return -EINVAL;
	*n_entries = sink.n;
	return 0;
}

struct semver {
	__u64		core[3];
	const char	*pre;
	size_t		pre_len;
};

/* SemVer 2.0.0, 9 and 10: identifiers of [0-9A-Za-z-], dot-separated. */
static bool semver_identifiers(const char *s, size_t len, bool prerelease)
{
	size_t i = 0;

	while (i < len) {
		size_t n = 0;

		while (i + n < len && s[i + n] != '.') {
			if (!isalnum((__u8)s[i + n]) && s[i + n] != '-')
				return false;
			n++;
		}
		if (!n || (prerelease && n > 1 && s[i] == '0' &&
			   digits(s + i, n) == n))
			return false;
		i += n;
		if (i < len && ++i == len)
			return false;
	}
	return len > 0;
}

static bool semver_parse(const char *s, struct semver *v)
{
	const char *p = s;
	size_t n;

	for (int i = 0; i < 3; i++) {
		n = digits(p, strlen(p));
		if (!n || (n > 1 && p[0] == '0') ||
		    parse_u64(p, n, UINT64_MAX, &v->core[i]))
			return false;
		p += n;
		if (i < 2 && *p++ != '.')
			return false;
	}
	v->pre = NULL;
	v->pre_len = 0;
	if (*p == '-') {
		n = span_until(p + 1, strlen(p + 1), "+");
		if (!semver_identifiers(p + 1, n, true))
			return false;
		v->pre = p + 1;
		v->pre_len = n;
		p += 1 + n;
	}
	if (*p == '+') {
		n = strlen(p + 1);
		if (!semver_identifiers(p + 1, n, false))
			return false;
		p += 1 + n;
	}
	return !*p;
}

/*
 * SemVer 2.0.0, 11.4: identifiers left to right, numeric ones by value
 * and below alphanumeric ones, a longer list after a shorter equal one.
 */
static int prerelease_compare(const char *a, size_t la, const char *b,
			      size_t lb)
{
	while (la && lb) {
		const char *da = memchr(a, '.', la), *db = memchr(b, '.', lb);
		size_t na = da ? (size_t)(da - a) : la;
		size_t nb = db ? (size_t)(db - b) : lb;
		bool numa = digits(a, na) == na, numb = digits(b, nb) == nb;
		int c;

		if (numa && numb) {
			c = na != nb ? (na > nb ? 1 : -1) : memcmp(a, b, na);
		} else if (numa != numb) {
			c = numa ? -1 : 1;
		} else {
			c = memcmp(a, b, min(na, nb));
			if (!c && na != nb)
				c = na > nb ? 1 : -1;
		}
		if (c)
			return c > 0 ? 1 : -1;
		a += na;
		la -= na;
		b += nb;
		lb -= nb;
		if (la) {
			a++;
			la--;
		}
		if (lb) {
			b++;
			lb--;
		}
	}
	return la ? 1 : lb ? -1 : 0;
}

bool bpm_semver_valid(const char *s)
{
	struct semver v;

	return s && semver_parse(s, &v);
}

/*
 * SemVer 2.0.0 precedence, build metadata ignored. A version it does not
 * describe sorts below every one it does, and such versions sort among
 * themselves by their bytes, so that the order stays total over every
 * version bpm_version_ok() lets through.
 */
int bpm_semver_compare(const char *a, const char *b)
{
	bool sa, sb;
	struct semver va, vb;
	int c;

	sa = semver_parse(a, &va);
	sb = semver_parse(b, &vb);
	if (!sa || !sb) {
		if (sa != sb)
			return sa ? 1 : -1;
		c = strcmp(a, b);
		return c > 0 ? 1 : c < 0 ? -1 : 0;
	}
	for (int i = 0; i < 3; i++) {
		if (va.core[i] != vb.core[i])
			return va.core[i] > vb.core[i] ? 1 : -1;
	}
	if (!va.pre_len || !vb.pre_len)
		return va.pre_len ? -1 : vb.pre_len ? 1 : 0;
	return prerelease_compare(va.pre, va.pre_len, vb.pre, vb.pre_len);
}

int bpm_verify_cms(const __u8 *payload, size_t payload_len,
		   const __u8 *sig, size_t sig_len, const char *cert_path)
{
	struct cert cert = {};
	int ret = -EINVAL;

	if (!cert_read_file(cert_path, &cert))
		ret = verify_detached(payload, payload_len, sig, sig_len, &cert);
	cert_free(&cert);
	return ret;
}

/*
 * Digits and nothing but blanks or NULs around them: a field read up to
 * its first stray byte, or a base-256 size read as zero, put the next
 * member where no other tar reader would.
 */
static int bpm_tar_octal(const char *p, size_t n, __u64 *out)
{
	size_t i = 0, first;
	__u64 v = 0;

	while (i < n && (p[i] == ' ' || p[i] == '\0'))
		i++;
	for (first = i; i < n && p[i] >= '0' && p[i] <= '7'; i++) {
		if (check_mul_overflow(v, 8, &v))
			return -EOVERFLOW;
		v |= (__u32)(p[i] - '0');
	}
	if (i == first)
		return -EINVAL;
	for (; i < n; i++) {
		if (p[i] != ' ' && p[i] != '\0')
			return -EINVAL;
	}
	*out = v;
	return 0;
}

/* The checksum is the header's byte sum with its own field as blanks. */
static bool bpm_tar_header_ok(const __u8 h[512])
{
	__u64 want, sum = 0;
	size_t i;

	if (bpm_tar_octal((const char *)h + 148, 8, &want))
		return false;
	for (i = 0; i < 512; i++)
		sum += i >= 148 && i < 156 ? ' ' : h[i];
	return sum == want;
}

bool bpm_archive_rel_ok(const char *name)
{
	const char *p = name, *q;
	size_t len;

	if (!name || !*name || *name == '/')
		return false;
	while (*p) {
		q = strchr(p, '/');
		if (!q)
			q = p + strlen(p);
		len = (size_t)(q - p);
		if (!len || span_equals(p, len, ".") || span_equals(p, len, ".."))
			return false;
		p = *q ? q + 1 : q;
	}
	return true;
}

enum bpm_upatch_member bpm_upatch_member(const char *name, size_t len)
{
	if (!len || name[0] == '.' || memchr(name, '\0', len))
		return BPM_UPATCH_OTHER;
	if (name_has_suffix(name, len, ".unload.upatch"))
		return BPM_UPATCH_UNLOAD;
	if (name_has_suffix(name, len, ".upatch"))
		return BPM_UPATCH_LOAD;
	return BPM_UPATCH_OTHER;
}

int bpm_upatch_pair(const char *name, size_t len, char *out, size_t cap)
{
	enum bpm_upatch_member kind = bpm_upatch_member(name, len);
	const char *from = kind == BPM_UPATCH_LOAD ? ".upatch" :
			   ".unload.upatch";
	const char *to = kind == BPM_UPATCH_LOAD ? ".unload.upatch" :
			 ".upatch";
	size_t base, n;

	if (kind == BPM_UPATCH_OTHER)
		return -EINVAL;
	base = len - strlen(from);
	n = strlen(to);
	if (base >= cap || n >= cap - base)
		return -ENAMETOOLONG;
	memcpy(out, name, base);
	memcpy(out + base, to, n + 1);
	return 0;
}

static bool package_member_name_ok(const char *name, const char *member)
{
	const char *slash;

	if (!bpm_archive_rel_ok(name) || !member)
		return false;
	slash = strchr(name, '/');
	return slash && slash != name && !str_has_prefix(name, "./") &&
		bpm_archive_rel_ok(member) && !strcmp(slash + 1, member);
}

/* A gzip stream from the start of fd, on a descriptor of its own. */
static gzFile package_gzdopen(int fd)
{
	gzFile gz;
	int copy;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return NULL;
	copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (copy < 0)
		return NULL;
	gz = gzdopen(copy, "rb");
	if (!gz) {
		close(copy);
		errno = ENOMEM;
	}
	return gz;
}

/*
 * A gzip stream of the file at path. zlib sets errno where a call it
 * makes fails and leaves it as it was where it refuses on its own.
 */
static gzFile package_gzopen(const char *path)
{
	gzFile gz;

	errno = 0;
	gz = gzopen(path, "rb");
	if (!gz && !errno)
		errno = ENOMEM;
	return gz;
}

/* Takes gz over, and its open's errno when it is NULL. */
static int read_member_gz(gzFile gz, const char *member,
			  const char *package_dir, char *found_dir,
			  size_t found_dir_sz, __u8 **out,
			  size_t *out_len, size_t max)
{
	int ret = -ENOENT;
	__u8 h[512];

	if (!gz)
		return -errno;
	if (gzdirect(gz)) {
		gzclose(gz);
		return -EINVAL;
	}
	for (;;) {
		int n = gzread(gz, h, sizeof(h));
		__u64 size, remain, pad;
		char name[101];
		bool zero = true;
		size_t alloc;

		if (n == 0)
			break;
		if (n != (int)sizeof(h)) {
			ret = -EINVAL;
			break;
		}
		for (size_t i = 0; i < sizeof(h); i++) {
			if (h[i]) {
				zero = false;
				break;
			}
		}
		if (zero)
			break;
		memcpy(name, h, 100);
		name[100] = '\0';
		if (!bpm_tar_header_ok(h) || !memchr(h, '\0', 100) ||
		    bpm_tar_octal((char *)h + 124, 12, &size)) {
			ret = -EINVAL;
			break;
		}
		remain = size;
		if (package_member_name_ok(name, member) &&
		    (!package_dir ||
		     span_equals_str(name, (size_t)(strchr(name, '/') - name),
				     package_dir))) {
			size_t dir_len = (size_t)(strchr(name, '/') - name);
			__u8 *body;

			if ((h[156] && h[156] != '0') || h[345] ||
			    (found_dir && dir_len >= found_dir_sz)) {
				ret = -EINVAL;
				break;
			}
			if (size > max || check_add_overflow(size, 1, &alloc)) {
				ret = -E2BIG;
				break;
			}
			body = xmalloc(alloc);
			if (!body) {
				ret = -ENOMEM;
				break;
			}
			while (remain) {
				size_t want = remain > 65536 ? 65536 : (size_t)remain;

				n = gzread(gz, body + size - remain, (__u32)want);
				if (n <= 0) {
					xfree(body, alloc);
					ret = -EINVAL;
					goto done;
				}
				remain -= (size_t)n;
			}
			body[size] = '\0';
			*out = body;
			*out_len = (size_t)size;
			if (found_dir) {
				memcpy(found_dir, name, dir_len);
				found_dir[dir_len] = '\0';
			}
			ret = 0;
			break;
		}
		while (remain) {
			__u8 discard[65536];
			size_t want = remain > sizeof(discard) ? sizeof(discard) : (size_t)remain;

			n = gzread(gz, discard, (__u32)want);
			if (n <= 0) {
				ret = -EINVAL;
				goto done;
			}
			remain -= (size_t)n;
		}
		pad = (512 - (size % 512)) % 512;
		while (pad) {
			__u8 discard[512];
			size_t want = pad > sizeof(discard) ? sizeof(discard) : (size_t)pad;

			n = gzread(gz, discard, (__u32)want);
			if (n <= 0) {
				ret = -EINVAL;
				goto done;
			}
			pad -= (size_t)n;
		}
	}
done:
	if (gzclose(gz) != Z_OK && ret == 0) {
		xfree(*out, *out_len + 1);
		*out = NULL;
		*out_len = 0;
		ret = -EINVAL;
	}
	return ret;
}

int bpm_pkg_read_member_in(const char *archive, const char *member,
			   const char *package_dir, char *found_dir,
			   size_t found_dir_sz, __u8 **out,
			   size_t *out_len, size_t max)
{
	return read_member_gz(package_gzopen(archive), member, package_dir,
			      found_dir, found_dir_sz, out, out_len, max);
}

int bpm_pkg_read_member_fd(int fd, const char *member,
			   const char *package_dir, char *found_dir,
			   size_t found_dir_sz, __u8 **out,
			   size_t *out_len, size_t max)
{
	return read_member_gz(package_gzdopen(fd), member, package_dir,
			      found_dir, found_dir_sz, out, out_len, max);
}

int bpm_pkg_read_member(const char *archive, const char *member,
			__u8 **out, size_t *out_len, size_t max)
{
	return bpm_pkg_read_member_in(archive, member, NULL, NULL, 0,
				      out, out_len, max);
}

/* Takes gz over, and its open's errno when it is NULL. */
static int visit_members_gz(gzFile gz, const char *package_dir,
			    bpm_pkg_member_fn visit, void *ctx)
{
	char root[256] = {};
	__u8 h[512];
	int ret = 0;

	if (!gz)
		return -errno;
	if (gzdirect(gz)) {
		gzclose(gz);
		return -EINVAL;
	}
	for (;;) {
		char name[PATH_MAX], rel[PATH_MAX], *slash;
		int n = gzread(gz, h, sizeof(h));
		__u64 size, remain, pad;
		size_t name_len, root_len;
		const char *below;
		bool zero = true;
		int type;

		if (n == 0)
			break;
		if (n != (int)sizeof(h)) {
			ret = -EINVAL;
			break;
		}
		for (size_t i = 0; i < sizeof(h); i++) {
			if (h[i]) {
				zero = false;
				break;
			}
		}
		if (zero)
			break;
		if (!bpm_tar_header_ok(h) || !memchr(h, '\0', 100) || h[345] ||
		    bpm_tar_octal((char *)h + 124, 12, &size)) {
			ret = -EINVAL;
			break;
		}
		if (strscpy(name, (char *)h, sizeof(name)) < 0) {
			ret = -EINVAL;
			break;
		}
		type = h[156] ? h[156] : '0';
		name_len = strlen(name);
		if (type == '5' && name_len && name[name_len - 1] == '/')
			name[--name_len] = '\0';
		if (!bpm_archive_rel_ok(name)) {
			ret = -EINVAL;
			break;
		}
		if (!root[0]) {
			slash = strchr(name, '/');
			if ((!slash && type != '5') || (slash && slash == name) ||
			    (slash ? (size_t)(slash - name) : name_len) >=
				    sizeof(root)) {
				ret = -EINVAL;
				break;
			}
			root_len = slash ? (size_t)(slash - name) : name_len;
			memcpy(root, name, root_len);
			root[root_len] = '\0';
		}
		below = str_after_prefix(name, root);
		if (!below || (*below && *below != '/')) {
			ret = -EINVAL;
			break;
		}
		if (package_dir && strcmp(root, package_dir)) {
			ret = -EINVAL;
			break;
		}
		if (type != '0' && type != '5') {
			ret = -EPERM;
			break;
		}
		if (strscpy(rel, below + (*below == '/'), sizeof(rel)) < 0) {
			ret = -EINVAL;
			break;
		}
		if (!*rel) {
			if (type != '5') {
				ret = -EINVAL;
				break;
			}
		} else if (!bpm_archive_rel_ok(rel)) {
			ret = -EINVAL;
			break;
		} else if (visit) {
			ret = visit(ctx, rel, (char)type);
			if (ret)
				break;
		}
		remain = size;
		while (remain) {
			__u8 discard[65536];
			size_t want = remain > sizeof(discard) ?
				      sizeof(discard) : (size_t)remain;

			n = gzread(gz, discard, (__u32)want);
			if (n <= 0) {
				ret = -EINVAL;
				goto done;
			}
			remain -= (size_t)n;
		}
		pad = (512 - (size % 512)) % 512;
		while (pad) {
			__u8 discard[512];
			size_t want = pad > sizeof(discard) ?
				      sizeof(discard) : (size_t)pad;

			n = gzread(gz, discard, (__u32)want);
			if (n <= 0) {
				ret = -EINVAL;
				goto done;
			}
			pad -= (size_t)n;
		}
	}
	if (!root[0])
		ret = -EINVAL;
done:
	if (gzclose(gz) != Z_OK && !ret)
		ret = -EINVAL;
	return ret;
}

int bpm_pkg_visit_members_fd(int fd, const char *package_dir,
			     bpm_pkg_member_fn visit, void *ctx)
{
	return visit_members_gz(package_gzdopen(fd), package_dir, visit, ctx);
}

static X509 *read_x509_memory(const __u8 *body, size_t len)
{
	BIO *b;
	X509 *x;

	if (len > INT_MAX)
		return NULL;
	b = BIO_new_mem_buf(body, (int)len);
	if (!b)
		return NULL;
	x = d2i_X509_bio(b, NULL);
	if (!x && BIO_reset(b) == 1)
		x = PEM_read_bio_X509(b, NULL, NULL, NULL);
	BIO_free(b);
	return x;
}

int bpm_pkg_extract(const char *archive, const char *dest)
{
	gzFile gz = gzopen(archive, "rb");
	char root[256] = {};
	__u64 total = 0;
	__u32 entries = 0;
	__u8 h[512];
	int ret = 0;

	if (!gz)
		return -EINVAL;
	ret = seal_mkdir_p(dest, 0700);
	if (ret) {
		gzclose(gz);
		return ret;
	}
	for (;;) {
		char name[PATH_MAX], rel[PATH_MAX], path[PATH_MAX], *slash;
		int n = gzread(gz, h, sizeof(h));
		__u64 size, remain, pad;
		const char *below;
		bool zero = true;
		int type;

		if (n == 0)
			break;
		if (n != (int)sizeof(h)) {
			ret = -EINVAL;
			break;
		}
		for (size_t i = 0; i < sizeof(h); i++) {
			if (h[i]) {
				zero = false;
				break;
			}
		}
		if (zero)
			break;
		/* A ustar prefix would make the member another reader's prefix/name. */
		if (!bpm_tar_header_ok(h) || !memchr(h, '\0', 100) || h[345]) {
			ret = -EINVAL;
			break;
		}
		if (strscpy(name, (char *)h, sizeof(name)) < 0) {
			ret = -EINVAL;
			break;
		}
		if (!bpm_archive_rel_ok(name) || bpm_tar_octal((char *)h + 124, 12, &size)) {
			ret = -EINVAL;
			break;
		}
		type = h[156];
		if (!type)
			type = '0';
		if (++entries > BPM_MAX_PACKAGE_ENTRIES ||
		    size > BPM_MAX_PACKAGE_BYTES - total) {
			ret = -EFBIG;
			break;
		}
		total += size;
		if (!root[0]) {
			slash = strchr(name, '/');
			if (!slash || slash == name || (size_t)(slash - name) >= sizeof(root)) {
				ret = -EINVAL;
				break;
			}
			memcpy(root, name, slash - name);
			root[slash - name] = 0;
		}
		below = str_after_prefix(name, root);
		if (!below || *below != '/') {
			ret = -EINVAL;
			break;
		}
		if (strscpy(rel, below + 1, sizeof(rel)) < 0 ||
		    (!*rel && type != '5') || (*rel && !bpm_archive_rel_ok(rel))) {
			ret = -EINVAL;
			break;
		}
		if (strsprintf(path, sizeof(path), "%s/%s", dest, rel) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		if (type == '5') {
			ret = seal_mkdir_p(path, 0700);
			if (ret)
				break;
			/* Read as the other walkers do, whatever a directory carries. */
			remain = size;
			while (remain) {
				__u8 buf[65536];
				size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain;

				n = gzread(gz, buf, (__u32)want);
				if (n <= 0) {
					ret = -EIO;
					break;
				}
				remain -= (size_t)n;
			}
			if (ret)
				break;
		} else if (type == '0') {
			char parent[PATH_MAX];
			int fd;

			if (strscpy(parent, path, sizeof(parent)) < 0) {
				ret = -ENAMETOOLONG;
				break;
			}
			slash = strrchr(parent, '/');
			if (slash) {
				*slash = 0;
				ret = seal_mkdir_p(parent, 0700);
				if (ret)
					break;
			}
			fd = seal_open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
			if (fd < 0) {
				ret = fd;
				break;
			}
			remain = size;
			while (remain) {
				__u8 buf[65536];
				size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain;

				n = gzread(gz, buf, (__u32)want);
				if (n <= 0 || write_complete(fd, buf, (size_t)n)) {
					ret = -EIO;
					break;
				}
				remain -= (size_t)n;
			}
			if (!ret && fchmod(fd, 0644))
				ret = -errno;
			close(fd);
			if (ret)
				break;
		} else {
			ret = -EPERM;
			break;
		}
		pad = (512 - (size % 512)) % 512;
		while (pad) {
			__u8 buf[512];
			size_t want = pad > sizeof(buf) ? sizeof(buf) : (size_t)pad;

			n = gzread(gz, buf, (__u32)want);
			if (n <= 0) {
				ret = -EINVAL;
				break;
			}
			pad -= (size_t)n;
		}
		if (ret)
			break;
	}
	if (gzclose(gz) != Z_OK && !ret)
		ret = -EINVAL;
	if (ret)
		return ret;
	return root[0] ? 0 : -EINVAL;
}

int bpm_pkg_load_info(const char *archive, struct bpm_package_info *info)
{
	__u8 *environment = NULL;
	struct {
		char name[BPM_MAX_NAME];
		char version[BPM_MAX_NAME];
		char signer[BPM_MAX_DIGEST];
	} parsed = {};
	struct json_field package_fields[2], shirudo_fields[1], root[2];
	struct cert signer = {};
	__u8 digest[32];
	X509 *cert = NULL;
	char hex[EVP_MAX_MD_SIZE * 2 + 1];
	size_t environment_len;
	int ret;

	memset(package_fields, 0, sizeof(package_fields));
	package_fields[0] = (struct json_field){
		.key = "name", .type = JSON_T_STRING,
		.dst = parsed.name, .dst_cap = sizeof(parsed.name),
	};
	package_fields[1] = (struct json_field){
		.key = "version", .type = JSON_T_STRING,
		.dst = parsed.version, .dst_cap = sizeof(parsed.version),
	};
	shirudo_fields[0] = (struct json_field){
		.key = "spki_sha256_fingerprint", .type = JSON_T_STRING,
		.dst = parsed.signer, .dst_cap = sizeof(parsed.signer),
	};
	root[0] = (struct json_field){
		.key = "package", .type = JSON_T_OBJECT,
		.sub = package_fields, .n_sub = ARRAY_SIZE(package_fields),
	};
	root[1] = (struct json_field){
		.key = "shirudo", .type = JSON_T_OBJECT,
		.sub = shirudo_fields, .n_sub = ARRAY_SIZE(shirudo_fields),
	};

	ret = bpm_pkg_read_member(archive, "build-environment.json", &environment,
				  &environment_len, 4u * 1024u * 1024u);
	if (ret)
		return ret;
	if (json_parse((const char *)environment, environment_len,
		       root, ARRAY_SIZE(root)) ||
	    !root[0].seen || !parsed.name[0] || !parsed.version[0] ||
	    !bpm_package_name_ok(parsed.name) || !bpm_version_ok(parsed.version)) {
		ret = -EINVAL;
		goto out;
	}

	ret = bpm_pkg_read_member(archive, "cert.der", &info->cert, &info->cert_len,
				  4u * 1024u * 1024u);
	if (ret)
		goto out;
	cert = read_x509_memory(info->cert, info->cert_len);
	signer.impl = cert;
	if (!cert || cert_pubkey_digest(&signer, digest)) {
		ret = -EINVAL;
		goto out;
	}
	hex_encode(digest, sizeof(digest), hex);
	if (parsed.signer[0] && !str_equals_nocase(parsed.signer, hex)) {
		pr_err("bpm: package signer fingerprint mismatch: "
		       "certificate=%s build-environment.json=%s",
		       hex, parsed.signer);
		ret = -EKEYREJECTED;
		goto out;
	}
	bpm_copy_string(info->name, sizeof(info->name), parsed.name);
	bpm_copy_string(info->version, sizeof(info->version), parsed.version);
	bpm_copy_string(info->signer, sizeof(info->signer), hex);
	ret = 0;
out:
	X509_free(cert);
	xfree(environment, environment_len + 1);
	if (ret) {
		xfree(info->cert, info->cert_len + 1);
		info->cert = NULL;
		info->cert_len = 0;
	}
	return ret;
}

int bpm_tree_manifest(const struct bpm_descriptor *payload,
		      const struct bpm_descriptor *sig, char *out, size_t cap,
		      size_t *len)
{
	static const char empty_config[] = "{}";
	struct bpm_descriptor config = { .size = sizeof(empty_config) - 1 };
	struct json_emit e = { .buf = out, .cap = cap };
	int ret;

	*len = 0;
	if (strscpy(config.media, BPM_EMPTY_CONFIG_MEDIA,
		    sizeof(config.media)) < 0)
		return -E2BIG;
	ret = bpm_sha256_digest(empty_config, sizeof(empty_config) - 1,
				config.digest, sizeof(config.digest));
	if (ret)
		return ret;
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", BPM_MANIFEST_MEDIA);
	json_kv_string(&e, "artifactType", BPM_TREE_ARTIFACT);
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, payload, NULL);
	bpm_oci_emit_descriptor(&e, NULL, sig, NULL);
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	*len = e.len;
	return 0;
}

/*
 * A registry may serve the signed layers under a manifest of its own
 * making: the manifest digest a node records and a successor names as
 * its parent would then be of bytes no signature covers, and a node that
 * recorded one form refuses the other for good. Only the form the
 * publisher writes is taken.
 */
static int tree_manifest_canonical(const struct bpm_buffer *manifest,
				   const struct bpm_descriptor *layers, int nl)
{
	size_t len;
	char *want;
	int ret;

	if (nl != 2 || strcmp(layers[0].media, BPM_TREE_MEDIA) ||
	    strcmp(layers[1].media, BPM_TREE_SIG_MEDIA))
		return -EBADMSG;
	want = xmalloc(BPM_TREE_MANIFEST_CAP);
	if (!want)
		return -ENOMEM;
	ret = bpm_tree_manifest(&layers[0], &layers[1], want,
				BPM_TREE_MANIFEST_CAP, &len);
	if (!ret && (len != manifest->len ||
		     memcmp(want, manifest->data, len)))
		ret = -EBADMSG;
	xfree(want, BPM_TREE_MANIFEST_CAP);
	return ret;
}

int bpm_tree_fetch_document(struct bpm_oci_client *c,
			    const char *repository, const char *reference,
			    const char *cert_path,
			    const struct trusted_set *trusted,
			    struct bpm_buffer *payload,
			    char *manifest_digest, size_t digest_sz)
{
	struct bpm_buffer manifest = {}, sig = {};
	struct bpm_descriptor *layers = NULL;
	char url[PATH_MAX];
	int nl = 0, ret;

	if (!reference[0] || strchr(reference, '/') || strchr(reference, '?') ||
	    strchr(reference, '#') || str_contains(reference, ".."))
		return -EINVAL;
	ret = bpm_oci_url(c, repository, "manifests", reference, url,
			  sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (ret)
		goto out;
	ret = bpm_sha256_digest(manifest.data, manifest.len, manifest_digest,
				digest_sz);
	if (ret)
		goto out;
	layers = xcalloc(BPM_MAX_ENTRIES, sizeof(*layers));
	if (!layers) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     BPM_MAX_ENTRIES, &nl, NULL, 0);
	if (!ret)
		ret = tree_manifest_canonical(&manifest, layers, nl);
	if (ret)
		goto out;
	ret = bpm_oci_get_signed(c, repository, layers, nl, BPM_TREE_MEDIA,
				 BPM_TREE_SIG_MEDIA, payload, &sig);
	if (ret)
		goto out;
	ret = trusted ? keys_verify_signature(trusted, payload->data,
					      payload->len, sig.data, sig.len,
					      NULL) :
	      bpm_verify_cms(payload->data, payload->len, sig.data, sig.len,
			     cert_path);
out:
	if (ret)
		bpm_buffer_free(payload);
	xfree(layers, BPM_MAX_ENTRIES * sizeof(*layers));
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&sig);
	return ret;
}

int bpm_tree_fetch_publication(struct bpm_oci_client *c,
			       const char *repository,
			       const char *reference,
			       const char *cert_path,
			       const struct trusted_set *trusted,
			       struct tree_publication *pub,
			       char *manifest_digest, size_t digest_sz)
{
	struct bpm_buffer payload = {};
	int ret;

	ret = bpm_tree_fetch_document(c, repository, reference, cert_path,
				      trusted, &payload, manifest_digest,
				      digest_sz);
	if (ret)
		return ret;
	ret = tree_parse((const char *)payload.data, payload.len, pub);
	bpm_buffer_free(&payload);
	return ret;
}
