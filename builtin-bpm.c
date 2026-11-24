// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The target's package manager; build, push and tree append are the
 * operator's and are dispatched to shirudo-build.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/bpm_oci.h"
#include "util/bpm_package.h"
#include "util/bpm_state.h"
#include "util/bpm_tree.h"
#include "util/bpm_source_config.h"
#include "util/chain.h"
#include "util/crypto.h"
#include "util/eventlog.h"
#include "util/format.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/initrd.h"
#include "util/java_agent.h"
#include "util/image_config.h"
#include "util/image_keys.h"
#include "util/keys.h"
#include "util/json.h"
#include "util/log.h"
#include "util/options.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/upatch.h"
#include "util/upatch_pins.h"
#include "util/upatch_rodata.h"

struct bpm_source {
	char name[BPM_MAX_NAME];
	char endpoint[BPM_MAX_ENDPOINT];
	char index_repository[BPM_MAX_ENDPOINT];
	char key_file[BPM_MAX_KEY];
};

static int sha256_file_hex(const char *path, char *hex, size_t hex_sz);
static int sha256_fd_hex(int fd, char *hex, size_t hex_sz);
static int remove_tree(const char *path);

static int prepare_direct_install(const char *raw, struct bpm_source *source,
				  struct bpm_index_entry *entry)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8];
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char package_name[BPM_MAX_NAME] = {};
	char endpoint[BPM_MAX_ENDPOINT];
	char url[PATH_MAX];
	int n_layers, ret;

	ret = bpm_oci_parse_pull_ref(raw, &c, repository, sizeof(repository), tag,
				     sizeof(tag));
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, repository, "manifests", tag, url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json",
				 &manifest);
	if (ret)
		goto out;
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &n_layers, package_name,
				     sizeof(package_name));
	if (ret)
		goto out;
	if (!package_name[0]) {
		const char *base = strrchr(repository, '/');

		bpm_copy_string(package_name, sizeof(package_name),
				base ? base + 1 : repository);
	}
	if (!bpm_package_name_ok(package_name)) {
		ret = -EINVAL;
		goto out;
	}
	if (strsprintf(endpoint, sizeof(endpoint), "oci://%s", c.registry) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	memset(source, 0, sizeof(*source));
	bpm_copy_string(source->name, sizeof(source->name), "direct");
	bpm_copy_string(source->endpoint, sizeof(source->endpoint), endpoint);
	memset(entry, 0, sizeof(*entry));
	bpm_copy_string(entry->name, sizeof(entry->name), package_name);
	bpm_copy_string(entry->version, sizeof(entry->version), tag);
	bpm_copy_string(entry->repository, sizeof(entry->repository), repository);
	/* package_install treats a non-digest reference as a tag. */
	bpm_copy_string(entry->manifest_digest, sizeof(entry->manifest_digest), tag);
	entry->package_size = -1;
	ret = 0;
out:
	bpm_buffer_free(&manifest);
	return ret;
}

/*
 * The registry names the layer without a signature, so its title names
 * the file only when it is a package name ending in .bee: never a path,
 * a hidden file, an option or a terminal control sequence.
 */
static bool bee_title_ok(const char *title)
{
	size_t n = strlen(title);

	return bpm_package_name_ok(title) && name_has_suffix(title, n, ".bee");
}

/*
 * Into the file open on fd at destination, or, without one, a new file
 * in the working directory named after the package. The registry picks
 * that name, so it is created, never an existing file replaced, and
 * opened as output root may ask for: never a sealed file nor one
 * reached through a link.
 */
/* The layer's title, else <package>-<tag>.bee. */
static int pull_filename(const char *repository, const char *tag,
			 const char *package_name, const char *title,
			 char *filename, size_t cap)
{
	const char *base = strrchr(repository, '/');

	if (bee_title_ok(title)) {
		bpm_copy_string(filename, cap, title);
		return 0;
	}
	base = base ? base + 1 : repository;
	if (package_name[0])
		base = package_name;
	if (!bpm_package_name_ok(base))
		return -EINVAL;
	if (strsprintf(filename, cap, "%s-%s.bee", base, tag) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * Download the package raw names into fd, or with fd -1 into a file of
 * the working directory, and check what was written there, read back
 * from the descriptor that wrote it.
 */
static int download_package(const char *raw, int fd)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8];
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char url[PATH_MAX], filename[PATH_MAX], title[PATH_MAX];
	char digest[65], package_name[BPM_MAX_NAME] = {};
	int n_layers = 0, out = fd, ret;

	ret = bpm_oci_parse_pull_ref(raw, &c, repository, sizeof(repository),
				     tag, sizeof(tag));
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, repository, "manifests", tag, url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json",
				 &manifest);
	if (ret)
		goto out;
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &n_layers, package_name,
				     sizeof(package_name));
	if (ret)
		goto out;
	bpm_trim(package_name, package_name, sizeof(package_name));
	for (int i = 0; i < n_layers; i++) {
		if (strcmp(layers[i].media, BPM_PACKAGE_MEDIA))
			continue;
		ret = bpm_oci_url(&c, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			goto out;
		/* A cut title would name another file; fall back to the package name. */
		if (bpm_trim(layers[i].title, title, sizeof(title)))
			title[0] = '\0';
		if (fd < 0) {
			ret = pull_filename(repository, tag, package_name, title,
					    filename, sizeof(filename));
			if (ret)
				goto out;
			out = seal_output_open(filename,
					       O_RDWR | O_CREAT | O_EXCL,
					       0644);
			if (out < 0) {
				ret = out;
				goto out;
			}
		}
		ret = bpm_oci_get_file(&c, url, BPM_PACKAGE_MEDIA, out,
				       layers[i].size);
		if (!ret && (sha256_fd_hex(out, digest, sizeof(digest)) ||
			     !bpm_digest_matches(layers[i].digest, digest)))
			ret = -EKEYREJECTED;
		if (!ret && layers[i].size >= 0) {
			struct stat st;

			if (fstat(out, &st) || st.st_size != layers[i].size)
				ret = -EKEYREJECTED;
		}
		if (fd < 0)
			close(out);
		if (ret && fd < 0)
			unlink(filename);
		goto out;
	}
	ret = -EINVAL;
out:
	bpm_buffer_free(&manifest);
	return ret;
}

static int pull_package(const char *raw)
{
	return download_package(raw, -1);
}

static int copy_file_ex(const char *src, const char *dst, mode_t mode,
			bool exclusive)
{
	struct stat in_st, out_st;
	int in, out, ret = 0;
	__u8 buf[65536];
	ssize_t n;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -errno;
	/* O_TRUNC on a destination that is the source would empty both. */
	if (!fstat(in, &in_st) && !stat(dst, &out_st) &&
	    in_st.st_dev == out_st.st_dev && in_st.st_ino == out_st.st_ino) {
		close(in);
		return exclusive ? -EEXIST : 0;
	}
	out = seal_open(dst, O_WRONLY | O_CREAT |
			(exclusive ? O_EXCL : O_TRUNC), mode);
	if (out < 0) {
		close(in);
		return out;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ret = write_complete(out, buf, (size_t)n);
		if (ret)
			break;
	}
	if (n < 0 && !ret)
		ret = -errno;
	if (fsync(out) && !ret)
		ret = -errno;
	close(in);
	close(out);
	if (ret)
		unlink(dst);
	return ret;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
	return copy_file_ex(src, dst, mode, false);
}

static int source_path(const char *name, char *out, size_t out_sz)
{
	if (!bpm_name_ok(name))
		return -EINVAL;
	if (strsprintf(out, out_sz, "%s/%s.conf", BPM_REGISTRIES_DIR, name) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * A stream on fd, or NULL with errno set. What comes from the config
 * image is authenticated content, and the host path it is named by in
 * messages is not where it was read from; only a host file has an owner
 * and mode to check, which open_trusted() does.
 */
static FILE *source_stream(int fd)
{
	if (fd < 0) {
		errno = -fd;
		return NULL;
	}
	return fdopen(fd, "r");
}

/* A source's file, from the config image's root when one is active. */
static FILE *source_open(const char *path)
{
	return source_stream(image_config_active() ?
			     image_open_relative(path + 1, O_RDONLY) :
			     open_trusted(path, O_RDONLY));
}

static DIR *registries_opendir(void)
{
	int fd;

	if (!image_config_active())
		return opendir(BPM_REGISTRIES_DIR);
	fd = image_open(IMAGE_REGISTRIES,
			O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		errno = -fd;
		return NULL;
	}
	return fdopendir(fd);
}

static int source_index_repository_valid(const char *endpoint,
					 const char *repository)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	char raw[PATH_MAX], parsed[BPM_MAX_ENDPOINT];
	const char *name = strrchr(repository, '/');
	int rc;

	if (!name || name == repository ||
	    strcmp(name + 1, BPM_INDEX_REPOSITORY_NAME))
		return -EINVAL;
	if (strsprintf(raw, sizeof(raw), "%s/%s", endpoint, repository) < 0)
		return -ENAMETOOLONG;
	rc = bpm_oci_parse_push_repo(raw, &c, parsed, sizeof(parsed));
	if (rc)
		return rc;
	return strcmp(parsed, repository) ? -EINVAL : 0;
}

static FILE *tree_conf_open(void)
{
	return source_stream(image_config_active() ?
			     image_open(IMAGE_TREE_CONF, O_RDONLY) :
			     open_trusted(BPM_TREE_ETC_PATH, O_RDONLY));
}

static int load_source(const char *name, struct bpm_source *s)
{
	char path[PATH_MAX], *line = NULL;
	size_t capacity = 0;
	int got, ret = 0;
	FILE *fp;

	memset(s, 0, sizeof(*s));
	ret = source_path(name, path, sizeof(path));
	if (ret)
		return ret;
	fp = source_open(path);
	if (!fp)
		return -errno;
	if (strscpy(s->name, name, sizeof(s->name)) < 0)
		ret = -ENAMETOOLONG;
	while (!ret && (got = read_text_line(fp, &line, &capacity,
					     PATH_MAX - 1)) != 0) {
		ret = got < 0 ? got :
		     bpm_parse_source_line(line,
					   s->endpoint, sizeof(s->endpoint),
					   s->index_repository,
					   sizeof(s->index_repository),
					   s->key_file, sizeof(s->key_file));
	}
	libc_free(line);
	fclose(fp);
	if (ret)
		return ret;
	if (!s->endpoint[0] || !s->key_file[0])
		return -EINVAL;
	if (!s->index_repository[0] &&
	    strsprintf(s->index_repository, sizeof(s->index_repository),
		       "%s/%s", s->name, BPM_INDEX_REPOSITORY_NAME) < 0)
		return -E2BIG;
	ret = source_index_repository_valid(s->endpoint,
					    s->index_repository);
	if (ret)
		return ret;
	/* With a config image the key file is the image's, named from its root. */
	if (image_config_active()) {
		if (str_has_prefix(s->key_file, "/etc/shirudo/bpm/keys/"))
			memmove(s->key_file, s->key_file + 1,
				strlen(s->key_file));
		if (s->key_file[0] == '/' || str_contains(s->key_file, ".."))
			return -EINVAL;
	}
	return 0;
}

static int source_cert(const struct bpm_source *s, struct cert *cert)
{
	int fd, ret;

	if (!image_config_active())
		return cert_read_file(s->key_file, cert);
	fd = image_open_relative(s->key_file, O_RDONLY);
	if (fd < 0)
		return fd;
	ret = cert_read_fd(fd, cert);
	close(fd);
	return ret;
}

static int save_source(const struct bpm_source *s)
{
	char path[PATH_MAX], data[PATH_MAX * 2];
	int ret = source_path(s->name, path, sizeof(path));

	if (ret)
		return ret;
	if (strsprintf(data, sizeof(data),
		       "endpoint = %s\nindex_repository = %s\nkey_file = %s\n",
		       s->endpoint, s->index_repository, s->key_file) < 0)
		return -E2BIG;
	return seal_write_file(path, data, strlen(data), 0644);
}

static int with_bpm_lock(void)
{
	int ret;

	ret = seal_mkdir_p(LOCKS_DIR, 0700);
	return ret ? ret : seal_lock(BPM_LOCK_PATH);
}

static int bpm_fail(const char *action, int ret)
{
	if (ret < 0)
		pr_err("bpm %s: %s", action, strerror(-ret));
	else
		pr_err("bpm %s failed", action);
	return 1;
}

/* The digest of fd's bytes from its start, whatever its offset. */
static int sha256_fd_hex(int fd, char *hex, size_t hex_sz)
{
	__u8 digest[CRYPTO_SHA256_LEN];
	struct sha256_ctx ctx;
	__u8 buf[65536];
	off_t at = 0;
	ssize_t nr;
	int ret = -EIO;

	if (hex_sz < 65 || sha256_init(&ctx) != 0)
		return -EINVAL;
	while ((nr = pread(fd, buf, sizeof(buf), at)) > 0) {
		if (sha256_update(&ctx, buf, (size_t)nr) != 0)
			goto done;
		at += nr;
	}
	if (nr < 0 || sha256_final(&ctx, digest) != 0)
		goto done;
	hex_encode(digest, sizeof(digest), hex);
	ret = 0;
done:
	sha256_free(&ctx);
	return ret;
}

static int sha256_file_hex(const char *path, char *hex, size_t hex_sz)
{
	int fd, ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = sha256_fd_hex(fd, hex, hex_sz);
	close(fd);
	return ret;
}

/*
 * A package the operator names, open for reading: the local file, or
 * the download in memory. Never a file of /tmp, which root can bind to a
 * sealed directory for shirudo to create a labeled file in.
 */
static int package_source_open(const char *source)
{
	int fd, ret;

	if (!str_has_prefix(source, "oci://")) {
		fd = open(source, O_RDONLY | O_CLOEXEC);
		return fd < 0 ? -errno : fd;
	}
	fd = memfd_create("shirudo-bpm-package", MFD_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = download_package(source, fd);
	if (ret) {
		close(fd);
		return ret;
	}
	return fd;
}

static int print_package_readme(const char *source)
{
	size_t beefile_len = 0, readme_len = 0;
	__u8 *beefile = NULL, *readme = NULL;
	char package_dir[101];
	int fd, ret;

	fd = package_source_open(source);
	if (fd < 0)
		return fd;
	ret = bpm_pkg_read_member_fd(fd, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &beefile_len,
				     4u * 1024u * 1024u);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info: package %s does not include Beefile", source);
		goto out;
	}
	ret = bpm_pkg_read_member_fd(fd, "README.md", package_dir, NULL, 0,
				     &readme, &readme_len, 4u * 1024u * 1024u);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info: package %s does not include README.md", source);
		goto out;
	}
	text_sanitize((char *)readme, readme_len, true);
	ret = write_complete(STDOUT_FILENO, readme, readme_len);
out:
	xfree(beefile, beefile_len + 1);
	xfree(readme, readme_len + 1);
	close(fd);
	return ret;
}

struct bpm_upatches_ctx {
	bool all;
	char *list;
	size_t len;
	size_t cap;
};

static int print_upatch_member(void *ctx, const char *member, char type)
{
	struct bpm_upatches_ctx *opts = ctx;
	size_t len = strlen(member), need, cap;
	enum bpm_upatch_member kind;
	const char *base = member;
	char *next;

	if (type != '0' || !str_skip_prefix(&base, "upatches/"))
		return 0;
	if (strchr(base, '/'))
		return 0;
	kind = bpm_upatch_member(base, strlen(base));
	if (kind == BPM_UPATCH_OTHER ||
	    (!opts->all && kind == BPM_UPATCH_UNLOAD))
		return 0;
	if (check_add_overflow(opts->len, len, &need) ||
	    check_add_overflow(need, 1, &need))
		return -EOVERFLOW;
	if (need > opts->cap) {
		cap = opts->cap ? opts->cap : 4096;
		while (cap < need) {
			if (cap > JSON_MAX_BYTES / 2) {
				cap = JSON_MAX_BYTES;
				break;
			}
			cap *= 2;
		}
		if (cap < need)
			return -E2BIG;
		next = xreallocarray(opts->list, opts->cap, cap, 1);
		if (!next)
			return -ENOMEM;
		opts->list = next;
		opts->cap = cap;
	}
	memcpy(opts->list + opts->len, member, len);
	text_sanitize(opts->list + opts->len, len, false);
	opts->list[opts->len + len] = '\n';
	opts->len = need;
	return 0;
}

static int print_package_upatches(const char *source, bool all)
{
	struct bpm_upatches_ctx ctx = { .all = all };
	size_t beefile_len = 0;
	__u8 *beefile = NULL;
	char package_dir[101];
	int fd, ret;

	fd = package_source_open(source);
	if (fd < 0)
		return fd;
	ret = bpm_pkg_read_member_fd(fd, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &beefile_len,
				     4u * 1024u * 1024u);
	if (!ret)
		ret = bpm_pkg_visit_members_fd(fd, package_dir,
					       print_upatch_member, &ctx);
	if (!ret && ctx.len)
		ret = write_complete(STDOUT_FILENO, ctx.list, ctx.len);
	if (ret == -ENOENT)
		pr_err("bpm info upatches: package %s does not include Beefile",
		       source);
	xfree(beefile, beefile_len + 1);
	xfree(ctx.list, ctx.cap);
	close(fd);
	return ret;
}

static int print_package_upatch_data(const char *source, const char *member,
				     bool json)
{
	size_t beefile_len = 0, upatch_len = 0;
	__u8 *beefile = NULL, *bytes = NULL;
	const char *base = member;
	char package_dir[101];
	struct upatch u = {};
	int fd, ret;

	if (!bpm_archive_rel_ok(member) ||
	    !str_skip_prefix(&base, "upatches/") || strchr(base, '/') ||
	    bpm_upatch_member(base, strlen(base)) == BPM_UPATCH_OTHER)
		return -EINVAL;
	fd = package_source_open(source);
	if (fd < 0)
		return fd;
	ret = bpm_pkg_read_member_fd(fd, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &beefile_len,
				     4u * 1024u * 1024u);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info data: package %s does not include Beefile",
			       source);
		goto out;
	}
	ret = bpm_pkg_read_member_fd(fd, member, package_dir, NULL, 0,
				     &bytes, &upatch_len,
				     UPATCH_FILE_MAX);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info data: package %s has no member %s",
			       source, member);
		goto out;
	}
	ret = upatch_open_memory(bytes, upatch_len, &u);
	if (ret) {
		pr_err("bpm info data: %s is not a valid upatch", member);
		goto out;
	}
	if (upatch_is_unload(&u)) {
		pr_err("bpm info data: %s is an unload directive", member);
		ret = -EINVAL;
		goto out;
	}
	ret = upatch_rodata_print(&u, member, json);
	if (ret == -ENODATA)
		pr_err("bpm info data: %s has no loader .rodata map data", member);
	else if (ret == -ENOENT || ret == -EOPNOTSUPP)
		pr_err("bpm info data: %s has no supported BTF .rodata data", member);
	else if (ret == -EINVAL)
		pr_err("bpm info data: cannot decode .rodata in %s", member);
out:
	upatch_close(&u);
	xfree(beefile, beefile_len + 1);
	xfree(bytes, upatch_len + 1);
	close(fd);
	return ret;
}

/* 0 when the certificate has the public key of the active cert.der. */
static int cert_matches_active(const __u8 *der, size_t len)
{
	struct cert a = {}, b = {};
	__u8 da[CRYPTO_SHA256_LEN], db[CRYPTO_SHA256_LEN];
	int ret = -EINVAL;

	if (!cert_read_memory(der, len, &a) &&
	    !cert_read_file(CERT_PATH, &b) &&
	    !cert_pubkey_digest(&a, da) &&
	    !cert_pubkey_digest(&b, db) &&
	    !memcmp(da, db, sizeof(da)))
		ret = 0;
	cert_free(&a);
	cert_free(&b);
	return ret;
}

static int cert_file_matches_active(const char *path)
{
	size_t len = 0;
	__u8 *der;
	int ret;

	ret = keys_read_der(path, &der, &len);
	if (ret)
		return ret;
	ret = cert_matches_active(der, len);
	xfree(der, len);
	return ret;
}

static int key_fingerprint(const __u8 *der, size_t len, char hex[65])
{
	__u8 digest[CRYPTO_SHA256_LEN];
	struct cert cert = {};
	int ret;

	ret = cert_read_memory(der, len, &cert);
	if (!ret)
		ret = cert_pubkey_digest(&cert, digest);
	cert_free(&cert);
	if (ret)
		return ret;
	hex_encode(digest, sizeof(digest), hex);
	return 0;
}

static int key_file_fingerprint(const char *path, char hex[65])
{
	size_t len = 0;
	__u8 *der;
	int ret;

	ret = keys_read_der(path, &der, &len);
	if (ret)
		return ret;
	ret = key_fingerprint(der, len, hex);
	xfree(der, len);
	return ret;
}

static int write_key(const char *dst, const __u8 *der, size_t len)
{
	int fd, ret;

	fd = seal_open(dst, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0)
		return fd;
	ret = write_complete(fd, der, len);
	if (!ret && fsync(fd))
		ret = -errno;
	if (close(fd) && !ret)
		ret = -errno;
	if (ret)
		unlink(dst);
	return ret;
}

static int install_key(const __u8 *der, size_t len)
{
	char hex[65], dst[PATH_MAX];
	bool active, made = false;
	struct stat st;
	int ret;

	ret = key_fingerprint(der, len, hex);
	if (ret)
		return ret;
	ret = seal_mkdir_p(KEYS_DIR, 0700);
	if (ret)
		return ret;
	active = lstat(CERT_PATH, &st) == 0;
	if (!active && errno != ENOENT)
		return -errno;
	if (active && cert_matches_active(der, len))
		return -EPERM;
	if (strsprintf(dst, sizeof(dst), "%s/%s.der", KEYS_DIR,
		       hex) < 0)
		return -ENAMETOOLONG;
	if (lstat(dst, &st) == 0) {
		char existing[65];

		if (!S_ISREG(st.st_mode) || key_file_fingerprint(dst, existing) ||
		    strcmp(existing, hex))
			return -EKEYREJECTED;
	} else {
		if (errno != ENOENT)
			return -errno;
		ret = write_key(dst, der, len);
		if (ret)
			return ret;
		made = true;
	}
	if (active)
		return 0;
	if (symlink(dst, CERT_PATH)) {
		if (errno != EEXIST) {
			ret = -errno;
			goto undo;
		}
		ret = cert_matches_active(der, len) ? -EPERM : 0;
		goto undo;
	}
	ret = seal_inherit_path(CERT_PATH);
undo:
	if (ret && made)
		unlink(dst);
	return ret;
}

/*
 * The DER certificate a key command takes, read once so that the key
 * installed is the one fingerprinted: the file named, or the cert.der of
 * a package, a download read in memory. *cap is what xfree() takes.
 */
static int key_source_read(const char *source, __u8 **der, size_t *len,
			   size_t *cap)
{
	size_t n = strlen(source);
	int fd, ret;

	if (!str_has_prefix(source, "oci://") &&
	    !name_has_suffix(source, n, ".bee")) {
		ret = keys_read_der(source, der, len);
		*cap = *len;
		return ret;
	}
	fd = package_source_open(source);
	if (fd < 0)
		return fd;
	ret = bpm_pkg_read_member_fd(fd, "cert.der", NULL, NULL, 0, der, len,
				     KEYS_DER_MAX);
	close(fd);
	*cap = *len + 1;
	return ret;
}

static int key_fingerprint_compare(const void *a, const void *b)
{
	return strcmp(*(char * const *)a, *(char * const *)b);
}

static int list_keys(bool json)
{
	char **fingerprints = NULL;
	size_t count = 0, cap = 0;
	struct dirent *entry;
	DIR *dir;
	int ret = 0;

	dir = opendir(KEYS_DIR);
	if (!dir && errno != ENOENT)
		return -errno;
	while (dir) {
		char path[PATH_MAX], hex[65], **next;
		struct stat st;
		bool valid = true;

		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			ret = -errno;
			break;
		}
		if (strlen(entry->d_name) != 68 ||
		    !str_equals_nocase(entry->d_name + 64, ".der"))
			continue;
		for (size_t i = 0; i < 64; i++) {
			if (!isxdigit((__u8)entry->d_name[i]))
				valid = false;
		}
		if (!valid || strsprintf(path, sizeof(path), "%s/%s",
					 KEYS_DIR, entry->d_name) < 0)
			continue;
		if (lstat(path, &st) || !S_ISREG(st.st_mode) ||
		    key_file_fingerprint(path, hex) ||
		    !str_after_prefix_nocase(entry->d_name, hex))
			continue;
		next = xreallocarray(fingerprints, cap, count + 1,
				     sizeof(*next));
		if (!next) {
			ret = -ENOMEM;
			break;
		}
		fingerprints = next;
		cap = count + 1;
		fingerprints[count] = xstrdup(hex);
		if (!fingerprints[count]) {
			ret = -ENOMEM;
			break;
		}
		count++;
	}
	if (dir)
		closedir(dir);
	if (!ret && count)
		qsort(fingerprints, count, sizeof(*fingerprints),
		      key_fingerprint_compare);
	if (!ret && json) {
		char buf[8192];
		struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_arr_open(&e, "fingerprints");
		for (size_t i = 0; i < count; i++)
			json_str(&e, fingerprints[i]);
		json_arr_close(&e);
		json_obj_close(&e);
		if (e.err)
			ret = e.err;
		else
			puts(buf);
	} else if (!ret) {
		printf("Package certificates:\n");
		if (!count)
			printf("  none\n");
		for (size_t i = 0; i < count; i++)
			printf("  %s\n", fingerprints[i]);
	}
	for (size_t i = 0; i < count; i++)
		xstrfree(fingerprints[i]);
	xfree(fingerprints, cap * sizeof(*fingerprints));
	return ret;
}

struct index_cache {
	char path[PATH_MAX];
	/* Name, endpoint, index repository and certificate digest, a line each. */
	char header[BPM_MAX_NAME + 2 * BPM_MAX_ENDPOINT + 2 * CRYPTO_SHA256_LEN + 2];
	size_t header_len;
};

static int index_cache_init(const struct bpm_source *source, const struct cert *cert,
			    struct index_cache *cache)
{
	__u8 digest[CRYPTO_SHA256_LEN];
	char hex[2 * sizeof(digest) + 1];
	int ret;

	ret = cert_sha256(cert, digest);
	if (ret)
		return ret;
	hex_encode(digest, sizeof(digest), hex);
	/* No field holds a newline, so the lines keep them apart. */
	ret = strsprintf(cache->header, sizeof(cache->header), "%s\n%s\n%s\n%s\n",
			 source->name, source->endpoint, source->index_repository, hex);
	if (ret < 0)
		return ret;
	cache->header_len = ret;
	if (strsprintf(cache->path, sizeof(cache->path), "%s/%s/index.cache",
		       BPM_REPOS_DIR, source->name) < 0)
		return -ENAMETOOLONG;
	return 0;
}

static int index_stale(const struct bpm_source *source)
{
	pr_err("bpm: refresh the index with 'shirudo bpm repo update %s'", source->name);
	return 1;
}

/*
 * Return 0 with the cached entries, 1 after reporting a source whose
 * certificate or verified index is unavailable, or a negative errno.
 */
static int load_cached_index(const struct bpm_source *source,
			     struct bpm_index_entry *entries, int *n)
{
	struct cert cert __cleanup(cert_free) = {};
	struct index_cache cache;
	__u8 *body;
	size_t len;
	int ret;

	ret = source_cert(source, &cert);
	if (ret) {
		pr_err("bpm: cannot read signing certificate for %s: %s",
		       source->name, strerror(-ret));
		return 1;
	}
	ret = index_cache_init(source, &cert, &cache);
	if (ret)
		return ret;
	ret = read_file(cache.path, cache.header_len + BPM_MAX_HTTP_BODY, &body, &len);
	if (ret == -ENOENT)
		return index_stale(source);
	if (ret)
		return ret;
	if (len >= cache.header_len && !memcmp(body, cache.header, cache.header_len))
		ret = bpm_index_parse(body + cache.header_len, len - cache.header_len,
				      entries, n);
	else
		ret = index_stale(source);
	xfree(body, len + 1);
	return ret;
}

static int cache_verified_index(const struct bpm_source *source, const struct cert *cert,
				const struct bpm_buffer *index)
{
	struct bpm_index_entry *entries;
	struct index_cache cache;
	char dir[PATH_MAX];
	size_t len;
	__u8 *body;
	int n, ret;

	entries = xcalloc(BPM_MAX_ENTRIES, sizeof(*entries));
	if (!entries)
		return -ENOMEM;
	ret = bpm_index_parse(index->data, index->len, entries, &n);
	xfree(entries, BPM_MAX_ENTRIES * sizeof(*entries));
	if (ret)
		return ret;
	ret = index_cache_init(source, cert, &cache);
	if (ret)
		return ret;
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPM_REPOS_DIR, source->name) < 0)
		return -ENAMETOOLONG;
	ret = seal_mkdir_p(dir, 0700);
	if (ret)
		return ret;
	len = cache.header_len + index->len;
	body = xmalloc(len);
	if (!body)
		return -ENOMEM;
	memcpy(body, cache.header, cache.header_len);
	memcpy(body + cache.header_len, index->data, index->len);
	ret = seal_write_file(cache.path, body, len, 0600);
	xfree(body, len);
	return ret;
}

static int repo_update_one(const char *name)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct cert cert __cleanup(cert_free) = {};
	struct bpm_buffer manifest = {}, index = {}, sig = {};
	struct bpm_descriptor layers[8];
	struct bpm_source s;
	char url[PATH_MAX];
	int nl, ret;

	ret = load_source(name, &s);
	if (ret)
		return ret;
	ret = source_cert(&s, &cert);
	if (ret)
		return ret;
	ret = bpm_oci_parse_endpoint(s.endpoint, &c);
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, s.index_repository, "manifests", BPM_INDEX_TAG,
			  url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (!ret)
		ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
					     ARRAY_SIZE(layers), &nl, NULL, 0);
	if (!ret)
		ret = bpm_oci_get_signed(&c, s.index_repository, layers, nl,
					 BPM_INDEX_MEDIA, BPM_INDEX_SIG_MEDIA, &index, &sig);
	if (!ret && verify_detached(index.data, index.len, sig.data, sig.len, &cert))
		ret = -EKEYREJECTED;
	if (!ret)
		ret = cache_verified_index(&s, &cert, &index);
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&index);
	bpm_buffer_free(&sig);
	return ret;
}

static int find_entry(const struct bpm_index_entry *e, int n, const char *name,
		      const char *version, struct bpm_index_entry *out)
{
	int found = -1;

	for (int i = 0; i < n; i++) {
		if (strcmp(e[i].name, name))
			continue;
		if (version && strcmp(e[i].version, version))
			continue;
		if (found < 0 ||
		    (!version && bpm_semver_compare(e[found].version,
						    e[i].version) < 0))
			found = i;
	}
	if (found < 0)
		return -ENOENT;
	*out = e[found];
	return 0;
}

static int path_compare(const void *left, const void *right)
{
	return strcmp(left, right);
}

/*
 * The old version's unload directives in reverse name order, as
 * uninstall runs them, each kept beside the load it undoes.
 */
static void sort_old_pairs(char (*unloads)[PATH_MAX], char (*loads)[PATH_MAX],
			   int n)
{
	char tmp[PATH_MAX];

	for (int i = 1; i < n; i++) {
		for (int j = i; j > 0 && strcmp(unloads[j - 1], unloads[j]) < 0;
		     j--) {
			memcpy(tmp, unloads[j], PATH_MAX);
			memcpy(unloads[j], unloads[j - 1], PATH_MAX);
			memcpy(unloads[j - 1], tmp, PATH_MAX);
			memcpy(tmp, loads[j], PATH_MAX);
			memcpy(loads[j], loads[j - 1], PATH_MAX);
			memcpy(loads[j - 1], tmp, PATH_MAX);
		}
	}
}

#define INSTALL_PATHS_MAX	128

static int package_install(const struct bpm_source *s, const struct bpm_index_entry *entry,
			   const char *old_path, const char *old_version)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8];
	int nl = 0;
	struct bpm_buffer manifest = {};
	char url[PATH_MAX], archive[PATH_MAX] = {}, dir[PATH_MAX], package_dir[PATH_MAX];
	char digest[65];
	int fd, ret;
	DIR *d;
	struct dirent *de;
	bool found_package = false, extracted = false;
	char (*loaded)[PATH_MAX], (*old_loads)[PATH_MAX], (*old_unloads)[PATH_MAX];
	int nloaded = 0, nactive = 0, nold = 0, nold_removed = 0;

	/* 1.5 MiB of paths, which a stack frame should not carry. */
	loaded = xcalloc(3 * INSTALL_PATHS_MAX, PATH_MAX);
	if (!loaded)
		return -ENOMEM;
	old_loads = loaded + INSTALL_PATHS_MAX;
	old_unloads = old_loads + INSTALL_PATHS_MAX;
	ret = bpm_oci_parse_endpoint(s->endpoint, &c);
	if (ret)
		goto out;
	ret = bpm_oci_url(&c, entry->repository[0] ? entry->repository : entry->name,
			  "manifests", entry->manifest_digest, url, sizeof(url));
	if (ret)
		goto out;
	ret = bpm_oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json", &manifest);
	if (ret)
		goto out;
	/*
	 * Repository indexes carry a sha256 manifest digest; direct OCI
	 * references carry the tag in this field and cannot be digest-checked.
	 */
	if (str_has_prefix(entry->manifest_digest, "sha256:")) {
		char manifest_hex[65];

		if (bpm_sha256_hex(manifest.data, manifest.len, manifest_hex,
				   sizeof(manifest_hex)) ||
		    !bpm_digest_matches(entry->manifest_digest, manifest_hex)) {
			ret = -EKEYREJECTED;
			goto out;
		}
	}
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &nl, NULL, 0);
	if (ret)
		goto out;
	for (int i = 0; i < nl; i++) {
		if (strcmp(layers[i].media, BPM_PACKAGE_MEDIA))
			continue;
		found_package = true;
		if (entry->package_digest[0] && strcmp(entry->package_digest, layers[i].digest)) {
			ret = -EKEYREJECTED;
			goto out;
		}
		if (entry->package_size > 0 && entry->package_size != layers[i].size) {
			ret = -EKEYREJECTED;
			goto out;
		}
		ret = bpm_oci_url(&c, entry->repository[0] ? entry->repository : entry->name,
				  "blobs", layers[i].digest, url, sizeof(url));
		if (ret)
			goto out;
		if (strsprintf(dir, sizeof(dir), "%s/%s", BPM_PACKAGES_DIR,
			       entry->name) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		ret = seal_mkdir_p(dir, 0700);
		if (ret)
			goto out;
		if (strsprintf(package_dir, sizeof(package_dir), "%s/%s", dir,
			       entry->version) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		ret = seal_mkdir_p(BPM_STAGING_DIR, 0700);
		if (ret)
			goto out;
		if (strsprintf(archive, sizeof(archive), "%s/%s-%s.bee",
			       BPM_STAGING_DIR, entry->name,
			       entry->version) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		fd = seal_open(archive, O_WRONLY | O_CREAT | O_TRUNC |
			       O_NOFOLLOW, 0600);
		if (fd < 0) {
			ret = fd;
			goto out;
		}
		ret = bpm_oci_get_file(&c, url, BPM_PACKAGE_MEDIA, fd,
				       layers[i].size);
		close(fd);
		if (ret) {
			unlink(archive);
			goto out;
		}
		if (sha256_file_hex(archive, digest, sizeof(digest)) ||
		    !bpm_digest_matches(layers[i].digest, digest)) {
			ret = -EKEYREJECTED;
			goto out;
		}
		if (access(package_dir, F_OK) == 0) {
			ret = -EEXIST;
			goto out;
		}
		extracted = true;
		ret = bpm_pkg_extract(archive, package_dir);
		if (ret)
			goto out;
		{
			char cert[PATH_MAX];

			if (strsprintf(cert, sizeof(cert), "%s/cert.der",
				       package_dir) < 0) {
				ret = -ENAMETOOLONG;
				goto out;
			}
			if (cert_file_matches_active(cert)) {
				ret = -EKEYREJECTED;
				goto out;
			}
		}
		{
			char updir[PATH_MAX];

			if (strsprintf(updir, sizeof(updir), "%s/upatches",
				       package_dir) < 0) {
				ret = -ENAMETOOLONG;
				goto out;
			}
			d = opendir(updir);
			if (!d) {
				ret = -errno;
				goto out;
			}
		}
		while ((de = readdir(d))) {
			char up[PATH_MAX];
			struct stat st;

			if (bpm_upatch_member(de->d_name, strlen(de->d_name)) !=
			    BPM_UPATCH_LOAD)
				continue;
			if (strsprintf(up, sizeof(up), "%s/upatches/%s", package_dir,
				       de->d_name) < 0) {
				ret = -ENAMETOOLONG;
				break;
			}
			if (stat(up, &st) || !S_ISREG(st.st_mode))
				continue;
			if (nloaded >= INSTALL_PATHS_MAX) {
				ret = -E2BIG;
				break;
			}
			if (strscpy(loaded[nloaded], up,
				    sizeof(loaded[nloaded])) < 0) {
				ret = -ENAMETOOLONG;
				break;
			}
			nloaded++;
		}
		closedir(d);
		if (ret || !nloaded) {
			if (!ret)
				ret = -EINVAL;
			goto out;
		}
		/* Measured in name order, not in the file system's. */
		qsort(loaded, (size_t)nloaded, sizeof(loaded[0]), path_compare);
		if (old_path && old_path[0]) {
			char olddir[PATH_MAX];

			if (strsprintf(olddir, sizeof(olddir), "%s/upatches",
				       old_path) < 0) {
				ret = -ENAMETOOLONG;
				goto out;
			}
			d = opendir(olddir);
			if (d) {
				while ((de = readdir(d))) {
					size_t len = strlen(de->d_name);
					char load[NAME_MAX + 1];

					if (bpm_upatch_member(de->d_name, len) !=
					    BPM_UPATCH_UNLOAD || nold >= INSTALL_PATHS_MAX)
						continue;
					if (bpm_upatch_pair(de->d_name, len, load,
							    sizeof(load)) ||
					    strsprintf(old_unloads[nold],
						       sizeof(old_unloads[nold]), "%s/%s",
						       olddir, de->d_name) < 0 ||
					    strsprintf(old_loads[nold],
						       sizeof(old_loads[nold]), "%s/%s",
						       olddir, load) < 0) {
						ret = -ENAMETOOLONG;
						break;
					}
					nold++;
				}
				closedir(d);
			}
			if (ret)
				goto out;
			sort_old_pairs(old_unloads, old_loads, nold);
			for (int old_i = 0; old_i < nold; old_i++) {
				if (upatch_remove(old_unloads[old_i])) {
					ret = -EIO;
					for (int restore_i = nold_removed - 1;
					     restore_i >= 0; restore_i--)
						upatch_install(old_loads[restore_i]);
					goto out;
				}
				nold_removed++;
			}
		}
		for (int loaded_i = 0; loaded_i < nloaded; loaded_i++) {
			if (upatch_install(loaded[loaded_i])) {
				ret = -EIO;
				goto rollback;
			}
			nactive++;
		}
		{
			char saved[PATH_MAX];

			if (strsprintf(saved, sizeof(saved), "%s/%s-%s.bee", dir,
				       entry->name, entry->version) < 0 ||
			    rename(archive, saved)) {
				pr_warn("bpm: cannot keep %s; dropping it",
					archive);
				unlink(archive);
			}
		}
		break;
	}
	if (!ret && !found_package)
		ret = -EINVAL;
	goto out;
rollback:
	for (int active_i = nactive - 1; active_i >= 0; active_i--) {
		const char *base = strrchr(loaded[active_i], '/');
		char unload[PATH_MAX], name[NAME_MAX + 1];

		if (!base ||
		    bpm_upatch_pair(base + 1, strlen(base + 1), name,
				    sizeof(name)) ||
		    strsprintf(unload, sizeof(unload), "%.*s/%s",
			       (int)(base - loaded[active_i]), loaded[active_i],
			       name) < 0)
			continue;
		upatch_remove(unload);
	}
	for (int restore_i = nold - 1; restore_i >= 0; restore_i--)
		upatch_install(old_loads[restore_i]);
out:
	bpm_buffer_free(&manifest);
	if (ret && archive[0])
		unlink(archive);
	/* What failed to install must not block the next attempt. */
	if (ret && extracted)
		remove_tree(package_dir);
	xfree(loaded, 3 * INSTALL_PATHS_MAX * PATH_MAX);
	return ret;
}

static int parse_package_ref(const char *raw, char *source, size_t ssz,
			     char *name, size_t nsz, char *version, size_t vsz)
{
	const char *slash, *at;

	if (!raw)
		return -EINVAL;
	slash = strchr(raw, '/');
	if (!slash || slash == raw)
		return -EINVAL;
	if ((size_t)(slash - raw) >= ssz)
		return -ENAMETOOLONG;
	memcpy(source, raw, slash - raw);
	source[slash - raw] = 0;
	at = strchr(slash + 1, '@');
	if (!at) {
		if (strscpy(name, slash + 1, nsz) < 0)
			return -ENAMETOOLONG;
		version[0] = 0;
	} else {
		if ((size_t)(at - slash - 1) >= nsz)
			return -ENAMETOOLONG;
		memcpy(name, slash + 1, at - slash - 1);
		name[at - slash - 1] = 0;
		if (strscpy(version, at + 1, vsz) < 0)
			return -ENAMETOOLONG;
	}
	return bpm_name_ok(source) && bpm_name_ok(name) &&
		(!version[0] || bpm_version_ok(version)) ? 0 : -EINVAL;
}

/* A usage error's status, or 0 where help or the option list was printed. */
static int bpm_exit(int ret)
{
	return ret == OPT_DONE ? 0 : EXIT_USAGE;
}

/*
 * The words of a bpm subcommand, from min to max of them into args, with
 * the value of each option given into values where there is one: OPT_END
 * to act, or OPT_DONE or OPT_USAGE to stop with. want names the words a
 * command short of min lacks.
 */
static int bpm_args(struct opt_parser *p, const char **values,
		    const char **args, size_t min, size_t max,
		    const char *want, size_t *n)
{
	int opt;

	*n = 0;
	for (opt = opt_next(p); opt != OPT_END; opt = opt_next(p)) {
		if (opt == OPT_DONE || opt == OPT_USAGE)
			return opt;
		if (opt != OPT_ARG) {
			if (values)
				values[opt] = p->value;
			continue;
		}
		if (*n == max) {
			opt_usage(p, "unexpected argument '%s'", p->value);
			return OPT_USAGE;
		}
		args[(*n)++] = p->value;
	}
	if (*n < min) {
		opt_usage(p, "takes %s", want);
		return OPT_USAGE;
	}
	return OPT_END;
}

enum bpm_register_add_opt {
	REGISTER_ADD_CERT,
	REGISTER_ADD_INDEX_REPOSITORY,
};

static const struct opt_spec bpm_register_add_opts[] = {
	[REGISTER_ADD_CERT] = { "--cert", 0, 0, "<certificate>",
		"the certificate the source's index and packages are signed for" },
	[REGISTER_ADD_INDEX_REPOSITORY] = { "--index-repository", 0, 0,
		"<repository>", "the repository of the signed index "
		"(default <source>/" BPM_INDEX_REPOSITORY_NAME ")" },
};

enum bpm_register_list_opt {
	REGISTER_LIST_JSON,
};

static const struct opt_spec bpm_register_list_opts[] = {
	[REGISTER_LIST_JSON] = { "--json", 0, 0, NULL,
		"print the registered sources as JSON" },
};

static const struct help_item bpm_config_subcmds[] = {
	{ "register", "register, list and remove OCI repositories" },
	{ "update", "build a config update package (operator)" },
};

static const struct help_item bpm_register_actions[] = {
	{ "add", "register a source and its certificate" },
	{ "list", "list the registered sources" },
	{ "remove", "remove a source and its certificate" },
};

static const struct help_section bpm_config_sections[] = {
	HELP_ITEMS("subcommands:", bpm_config_subcmds),
	HELP_ITEMS("register actions:", bpm_register_actions),
	HELP_OPTIONS("register add options:", bpm_register_add_opts),
	HELP_OPTIONS("register list options:", bpm_register_list_opts),
};

static const struct help bpm_config_help = {
	.usage	    = "shirudo bpm config register add <source> oci://<registry> "
		      "--cert <certificate>\n"
		      "           [--index-repository <repository>]\n"
		      "       shirudo bpm config register list [--json]\n"
		      "       shirudo bpm config register remove <source>\n"
		      "       shirudo bpm config update --base-package "
		      "<package.bee|oci://host/repo:tag> --version <version> "
		      "[--file <name>.bee] [options]",
	.summary    = "Register the OCI repositories packages come from, or "
		      "build a config\nupdate package (operator).",
	.sections   = bpm_config_sections,
	.n_sections = ARRAY_SIZE(bpm_config_sections),
};

static int bpm_register_list(int argc, const char **argv)
{
	char buf[8192];
	struct json_emit je = { .buf = buf, .cap = sizeof(buf) };
	struct opt_parser p;
	struct dirent *e;
	size_t count = 0, n;
	bool json;
	DIR *d;
	int ret;

	OPT_INIT(&p, "bpm config register list", bpm_register_list_opts,
		 &bpm_config_help, argc, argv, 3);
	ret = bpm_args(&p, NULL, NULL, 0, 0, NULL, &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	json = opt_given(&p, REGISTER_LIST_JSON);
	d = registries_opendir();
	if (json) {
		json_obj_open(&je);
		json_kv_int(&je, "schema", 1);
		json_arr_open(&je, "sources");
	} else {
		printf("Registered sources:\n");
	}
	while (d && (e = readdir(d))) {
		size_t len = strlen(e->d_name);
		char name[NAME_MAX + 1];

		if (!name_has_suffix(e->d_name, len, ".conf") ||
		    strsprintf(name, sizeof(name), "%.*s",
			       (int)(len - 5), e->d_name) < 0)
			continue;
		if (json)
			json_str(&je, name);
		else
			printf("  %s\n", name);
		count++;
	}
	if (d)
		closedir(d);
	if (json) {
		json_arr_close(&je);
		json_obj_close(&je);
		if (je.err)
			return 1;
		puts(buf);
	} else if (!count) {
		printf("  none\n");
	}
	return 0;
}

static int bpm_register_remove(int argc, const char **argv,
			       const char *command)
{
	char p_conf[PATH_MAX], key[PATH_MAX];
	struct bpm_source s;
	struct opt_parser p;
	const char *name;
	size_t n;
	int ret;

	opt_init(&p, command, NULL, 0, &bpm_config_help, argc, argv, 3);
	ret = bpm_args(&p, NULL, &name, 1, 1, "<source>", &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	if (image_config_active()) {
		pr_err("image mode: change repository definitions and keys in "
		       "a signed config image, then run `shirudo image update`");
		return 1;
	}
	if (source_path(name, p_conf, sizeof(p_conf)))
		return EXIT_USAGE;
	if (load_source(name, &s) == 0 && s.key_file[0])
		unlink(s.key_file);
	if (unlink(p_conf) && errno != ENOENT)
		return 1;
	if (strsprintf(key, sizeof(key), "%s/%s.der", BPM_KEYS_DIR, name) >= 0)
		unlink(key);
	return 0;
}

static int bpm_register_add(int argc, const char **argv)
{
	struct bpm_oci_client probe __cleanup(bpm_oci_client_clear) = {};
	const char *values[ARRAY_SIZE(bpm_register_add_opts)] = {};
	struct bpm_source s = {};
	const char *args[2], *key;
	char managed[PATH_MAX];
	struct cert cert = {};
	struct opt_parser p;
	size_t n;
	int ret;

	OPT_INIT(&p, "bpm config register add", bpm_register_add_opts,
		 &bpm_config_help, argc, argv, 3);
	ret = bpm_args(&p, values, args, 2, 2, "<source> and oci://<registry>",
		       &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	if (image_config_active()) {
		pr_err("image mode: change repository definitions and keys in "
		       "a signed config image, then run `shirudo image update`");
		return 1;
	}
	key = values[REGISTER_ADD_CERT];
	if (!key) {
		opt_usage(&p, "takes --cert <certificate>");
		return EXIT_USAGE;
	}
	if (strscpy(s.name, args[0], sizeof(s.name)) < 0 ||
	    strscpy(s.endpoint, args[1], sizeof(s.endpoint)) < 0) {
		opt_usage(&p, "name or endpoint too long");
		return EXIT_USAGE;
	}
	if (values[REGISTER_ADD_INDEX_REPOSITORY]) {
		if (strscpy(s.index_repository,
			    values[REGISTER_ADD_INDEX_REPOSITORY],
			    sizeof(s.index_repository)) < 0)
			return EXIT_USAGE;
	} else if (strsprintf(s.index_repository, sizeof(s.index_repository),
			      "%s/%s", s.name, BPM_INDEX_REPOSITORY_NAME) < 0) {
		return EXIT_USAGE;
	}
	if (cert_read_file(key, &cert) ||
	    !bpm_name_ok(s.name) ||
	    bpm_oci_parse_endpoint(s.endpoint, &probe) ||
	    source_index_repository_valid(s.endpoint, s.index_repository)) {
		cert_free(&cert);
		pr_err("bpm: register add requires a valid endpoint, index repository and --cert certificate");
		return EXIT_USAGE;
	}
	cert_free(&cert);
	if (seal_mkdir_p(BPM_REGISTRIES_DIR, 0700) ||
	    seal_mkdir_p(BPM_KEYS_DIR, 0700))
		return 1;
	if (strsprintf(managed, sizeof(managed), "%s/%s.der",
		       BPM_KEYS_DIR, s.name) < 0)
		return 1;
	if (copy_file(key, managed, 0644))
		return 1;
	if (strlen(managed) >= sizeof(s.key_file))
		return 1;
	bpm_copy_string(s.key_file, sizeof(s.key_file), managed);
	return save_source(&s) ? 1 : 0;
}

static int cmd_bpm_config(int argc, const char **argv)
{
	const char *action = argc > 2 ? argv[2] : NULL;

	if (argc < 2 || is_help(argv[1])) {
		print_help(&bpm_config_help);
		return argc < 2 ? EXIT_USAGE : 0;
	}
	if (is_list_cmds(argv[1])) {
		print_subcmd_list(bpm_config_subcmds,
				  ARRAY_SIZE(bpm_config_subcmds));
		return 0;
	}
	if (strcmp(argv[1], "register")) {
		pr_err("bpm config: '%s' is not a subcommand", argv[1]);
		return EXIT_USAGE;
	}
	if (!action || is_help(action)) {
		print_help(&bpm_config_help);
		return action ? 0 : EXIT_USAGE;
	}
	if (is_list_cmds(action)) {
		print_subcmd_list(bpm_register_actions,
				  ARRAY_SIZE(bpm_register_actions));
		return 0;
	}
	if (!strcmp(action, "list"))
		return bpm_register_list(argc, argv);
	if (!strcmp(action, "add"))
		return bpm_register_add(argc, argv);
	if (!strcmp(action, "remove") || !strcmp(action, "rm"))
		return bpm_register_remove(argc, argv, !strcmp(action, "rm") ?
					   "bpm config register rm" :
					   "bpm config register remove");
	pr_err("bpm config register: '%s' is not an action", action);
	return EXIT_USAGE;
}

struct bpm_tree_config {
	char endpoint[BPM_MAX_ENDPOINT];
	char reference[BPM_MAX_DIGEST];
};

static int load_tree_config(struct bpm_tree_config *cfg)
{
	size_t capacity = 0;
	char *line = NULL;
	int got, ret = 0;
	FILE *fp;

	*cfg = (struct bpm_tree_config){};
	fp = tree_conf_open();
	if (!fp)
		return -errno;
	while (!ret && (got = read_text_line(fp, &line, &capacity,
					     PATH_MAX - 1)) != 0) {
		if (got < 0 ||
		    bpm_parse_tree_line(line, cfg->endpoint,
					sizeof(cfg->endpoint),
					cfg->reference,
					sizeof(cfg->reference)))
			ret = -EINVAL;
	}
	libc_free(line);
	fclose(fp);
	if (ret)
		return ret;
	if (!cfg->endpoint[0] || !cfg->reference[0])
		return -EINVAL;
	return 0;
}

static bool tree_digest_valid(const char *digest)
{
	__u8 raw[32];

	return !sha256_digest_decode(digest, raw);
}

struct tree_source {
	struct bpm_oci_client c;
	char repository[BPM_MAX_ENDPOINT];
	struct trusted_set *trusted;
};

static void tree_source_clear(struct tree_source *src)
{
	bpm_oci_client_clear(&src->c);
	xfree(src->trusted, sizeof(*src->trusted));
	src->trusted = NULL;
}

/* The signing set is loaded once, for every segment a walk fetches. */
static int tree_source_open(const struct bpm_tree_config *cfg,
			    struct tree_source *src)
{
	int ret;

	ret = bpm_oci_parse_tree_repo(cfg->endpoint, &src->c,
				      src->repository, sizeof(src->repository));
	if (ret || !image_config_active())
		return ret;
	src->trusted = xcalloc(1, sizeof(*src->trusted));
	if (!src->trusted)
		return -ENOMEM;
	ret = keys_load_image_root(get_cert_path(), image_config_root_fd(),
				   true, src->trusted);
	if (!ret && (!src->trusted->n || src->trusted->n_unvouched))
		ret = -EKEYREJECTED;
	if (!ret)
		ret = keys_check_image_set(src->trusted);
	return ret;
}

static int tree_verify_upatch(const char *path, const char *expected,
			      const char *id, bool unload)
{
	struct upatch u;
	char name[UPATCH_NAME_MAX + 1];
	char actual[65];
	int ret = upatch_open(path, &u);

	if (ret)
		return ret;
	upatch_header_name(&u, name);
	hex_encode(u.hdr.payload_sha256, 32, actual);
	if (!bpm_digest_matches(expected, actual) ||
	    (id && strcmp(name, id)) ||
	    upatch_is_unload(&u) != unload)
		ret = -EKEYREJECTED;
	upatch_close(&u);
	return ret;
}

static int tree_pull_artifact(const struct tree_operation *op,
			      char *path, size_t path_sz)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	char repository[BPM_MAX_ENDPOINT], url[PATH_MAX], cache[PATH_MAX];
	struct bpm_buffer manifest = {}, blob = {};
	struct bpm_descriptor *layers = NULL;
	char hex[65];
	int nl = 0, ret;

	if (!tree_digest_valid(op->artifact.layer_digest))
		return -EINVAL;
	/*
	 * The cache holds the blob exactly as fetched, so its content
	 * address names it. The payload digest would not: equally built
	 * upatches published under different names share it.
	 */
	if (strsprintf(cache, sizeof(cache), "%s/%s.upatch",
		       BPM_TREE_ARTIFACTS_DIR,
		       op->artifact.layer_digest + strlen("sha256:")) < 0)
		return -ENAMETOOLONG;
	if (!access(cache, R_OK)) {
		bpm_copy_string(path, path_sz, cache);
		return tree_verify_upatch(path, op->artifact.payload_sha256, op->id,
					  !strcmp(op->op, "delete"));
	}
	ret = bpm_oci_parse_tree_repo(op->artifact.repository, &c, repository,
				      sizeof(repository));
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, repository, "manifests",
			  op->artifact.manifest_digest, url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json", &manifest);
	if (ret)
		goto out;
	if (bpm_sha256_hex(manifest.data, manifest.len, hex, sizeof(hex)) ||
	    !bpm_digest_matches(op->artifact.manifest_digest, hex)) {
		ret = -EKEYREJECTED;
		goto out;
	}
	layers = xcalloc(BPM_MAX_ENTRIES, sizeof(*layers));
	if (!layers) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     BPM_MAX_ENTRIES, &nl, NULL, 0);
	if (ret)
		goto out;
	for (int i = 0; i < nl; i++) {
		if (strcmp(layers[i].digest, op->artifact.layer_digest) ||
		    strcmp(layers[i].media, BPM_UPATCH_MEDIA))
			continue;
		ret = bpm_oci_url(&c, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			goto out;
		ret = bpm_oci_get_blob(&c, url, layers[i].media, &blob);
		if (ret)
			goto out;
		if (bpm_sha256_hex(blob.data, blob.len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex) ||
		    (layers[i].size >= 0 && (__s64)blob.len != layers[i].size))
			ret = -EKEYREJECTED;
		if (ret)
			goto out;
		ret = seal_mkdir_p(BPM_TREE_ARTIFACTS_DIR, 0700);
		if (ret)
			goto out;
		ret = seal_write_file(cache, blob.data, blob.len, 0600);
		if (ret)
			goto out;
		bpm_copy_string(path, path_sz, cache);
		ret = tree_verify_upatch(path, op->artifact.payload_sha256, op->id,
					 !strcmp(op->op, "delete"));
		goto out;
	}
	ret = -ENOENT;
out:
	xfree(layers, BPM_MAX_ENTRIES * sizeof(*layers));
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&blob);
	return ret;
}

static int tree_write_report(const char *path, const struct tree_state *s,
			     int selected, int skipped, int applied,
			     int module_skipped, int dry_run,
			     int tpm_available)
{
	char buf[4096];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_bool(&e, "dry_run", dry_run);
	json_kv_int(&e, "selected", selected);
	json_kv_int(&e, "skipped", skipped);
	json_kv_int(&e, "applied", applied);
	json_kv_int(&e, "module_skipped", module_skipped);
	json_kv_bool(&e, "tpm_available", tpm_available);
	json_kv_int(&e, "last_seq", s->last_seq);
	if (tpm_available)
		json_kv_string(&e, "projection_root_tpm",
			       s->projection_root_tpm);
	else
		json_kv_null(&e, "projection_root_tpm");
	json_obj_close(&e);
	if (e.err)
		return e.err;
	if (path) {
		struct seal_output out;
		int ret;

		ret = seal_output_create(&out, path, 0600);
		return ret ? ret : seal_output_commit(&out, buf, e.len);
	}
	printf("%s\n", buf);
	return 0;
}

static int tree_status_write(const char *id, const char *status)
{
	char path[PATH_MAX];
	int ret;

	if (!id || !upatch_name_valid(id) || !status || !status[0])
		return -EINVAL;
	ret = seal_mkdir_p(BPM_TREE_STATUS_DIR, 0700);
	if (ret)
		return ret;
	if (strsprintf(path, sizeof(path), "%s/%s",
		       BPM_TREE_STATUS_DIR, id) < 0)
		return -ENAMETOOLONG;
	return seal_write_file(path, status, strlen(status), 0600);
}

static void tree_status_clear(const char *id)
{
	char path[PATH_MAX];

	if (!id || !upatch_name_valid(id) ||
	    strsprintf(path, sizeof(path), "%s/%s",
		       BPM_TREE_STATUS_DIR, id) < 0)
		return;
	unlink(path);
}

static int tree_status_update(const char *id, bool module_absent)
{
	if (!module_absent) {
		tree_status_clear(id);
		return 0;
	}
	return tree_status_write(id, "skipped: module not loaded");
}

/*
 * event = SHA256("shirudo-tree\0" || seq || operation_digest). The
 * tree's own projection stays a file chain; the register is what an
 * operator attests.
 */
/* The record of a tree operation up to the register value that ends it. */
static void tree_record_open(struct json_emit *e,
			     const struct tree_operation *op,
			     const __u8 event[32])
{
	eventlog_record_open(e, "tree_op", event);
	json_obj_open_key(e, "tree");
	json_kv_int(e, "seq", op->seq);
	json_kv_string(e, "op", op->op);
	json_kv_string(e, "id", op->id);
	json_kv_string(e, "operation_digest", op->operation_digest);
	json_obj_close(e);
}

/* On a copy of the emitter, whose buffer is fixed, to end the record twice. */
static int tree_record_close(struct json_emit e, const __u8 chain[32])
{
	char chain_hex[65];

	hex_encode(chain, 32, chain_hex);
	json_kv_string(&e, "chain", chain_hex);
	json_obj_close(&e);
	return e.err;
}

static int tree_measure_locked(const struct tree_operation *op,
			       const __u8 operation_digest[32])
{
	__u8 event[32], chain[32] = {};
	struct json_emit e;
	char line[4096];
	int ret;

	ret = chain_tree_event(op->seq, operation_digest, event);
	if (ret)
		return ret;
	/*
	 * The record is written out before the extend, which nothing takes
	 * back, though it ends in the value the extend gives: ended here
	 * with a value of the same length, it ends with the real one the
	 * same way. A record that could fail after the extend would leave
	 * the register ahead of the log.
	 */
	e = (struct json_emit){ .buf = line, .cap = sizeof(line) };
	tree_record_open(&e, op, event);
	ret = tree_record_close(e, chain);
	if (!ret)
		ret = chain_extend(event, chain);
	if (ret)
		return ret;
	ret = tree_record_close(e, chain);
	return ret ? ret : eventlog_append(line);
}

static int tree_measure_operation(const struct tree_operation *op,
				  const __u8 operation_digest[32])
{
	int lock, ret;

	lock = eventlog_lock();
	if (lock < 0)
		return lock;
	ret = tree_measure_locked(op, operation_digest);
	eventlog_unlock(lock);
	return ret;
}

static int tree_outcome_record(__s64 seq, const __u8 operation_digest[32],
			       enum tree_outcome outcome,
			       const __u8 projection_root[32],
			       __u8 history_root[32])
{
	int ret;

	ret = chain_history_step(history_root, operation_digest, history_root);
	if (ret)
		return ret;
	return tree_outcome_append(seq, outcome, projection_root, history_root);
}

static int tree_outcome_unmatched(const struct tree_operation *op,
				  const __u8 projection_root[32],
				  __u8 history_root[32])
{
	__u8 digest[32];

	if (sha256_digest_decode(op->operation_digest, digest))
		return -EINVAL;
	return tree_outcome_record(op->seq, digest, TREE_OUTCOME_UNMATCHED,
				   projection_root, history_root);
}

/*
 * The operations between the cursor and the pending one had no match in
 * the sync that stopped: it would have committed the cursor at one that
 * had.
 */
static int tree_outcomes_passed(const struct tree_publication *pub,
				__s64 last_seq, __s64 pending_seq,
				const __u8 projection_root[32],
				__u8 history_root[32])
{
	int ret;

	for (int i = 0; i < pub->n_operations; i++) {
		const struct tree_operation *op = &pub->operations[i];

		if (op->seq >= pending_seq)
			break;
		if (op->seq <= last_seq)
			continue;
		ret = tree_outcome_unmatched(op, projection_root, history_root);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Complete the only non-idempotent window: the process may have
 * measured the operation, or appended its tree event too, before the
 * sealed cursor was committed. Applying it again would extend the
 * register with it a second time this boot. The install's answer went
 * with the process, so an add whose upatch is not loaded is one whose
 * module was absent.
 */
static int tree_recover_pending(const struct tree_publication *pub,
				struct tree_state *state,
				__u8 history_root[32])
{
	struct tree_pending pending;
	const struct tree_operation *op = NULL;
	__u8 digest[32], previous[32], next[32], replay[32];
	bool applied = false, event_present = false, absent;
	int ret;

	ret = tree_pending_read(&pending);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;
	/*
	 * The cursor was committed past it, whatever came of it: the
	 * publication may since have moved on to a segment that no longer
	 * holds it.
	 */
	if (pending.seq <= state->last_seq) {
		unlink(BPM_TREE_PENDING_PATH);
		return 0;
	}
	for (int i = 0; i < pub->n_operations; i++) {
		if (pub->operations[i].seq == pending.seq &&
		    !strcmp(pub->operations[i].id, pending.id) &&
		    !strcmp(pub->operations[i].operation_digest,
			    pending.operation_digest)) {
			op = &pub->operations[i];
			break;
		}
	}
	if (!op)
		return -ERANGE;
	if (sha256_digest_decode(pending.operation_digest, digest) ||
	    hex_decode(state->projection_root, previous, 32))
		return -EINVAL;
	ret = sha256_2(previous, sizeof(previous), digest, sizeof(digest),
		       next);
	if (ret)
		return ret;

	ret = tree_event_replay(replay);
	if (!ret) {
		if (!memneq_explicit(replay, next, sizeof(replay))) {
			applied = true;
			event_present = true;
		} else if (memneq_explicit(replay, previous, sizeof(replay))) {
			return -EKEYREJECTED;
		}
	} else if (ret != -ENOENT) {
		return -EKEYREJECTED;
	}
	if (!applied) {
		ret = eventlog_tree_op_measured(op->seq, op->operation_digest);
		if (ret < 0)
			return -EKEYREJECTED;
		/* Still pre-operation; retry normally. */
		if (!ret)
			return 0;
	}
	if (!event_present) {
		ret = tree_event_append(op->seq, op->operation_digest, next);
		if (ret)
			return ret;
	}
	ret = tree_outcomes_passed(pub, state->last_seq, op->seq, previous,
				   history_root);
	if (ret)
		return ret;
	absent = !strcmp(op->op, "add") && !upatch_loaded_pins(op->id) &&
		 !java_agent_loaded(op->id);
	ret = tree_outcome_record(op->seq, digest,
				  absent ? TREE_OUTCOME_MODULE_ABSENT :
					   TREE_OUTCOME_APPLIED,
				  next, history_root);
	if (ret)
		return ret;
	hex_encode(next, sizeof(next), state->projection_root);
	hex_encode(next, sizeof(next), state->projection_root_tpm);
	state->last_seq = op->seq;
	ret = tree_state_write(state);
	if (!ret)
		ret = tree_status_update(op->id, absent);
	if (ret)
		return ret;
	unlink(BPM_TREE_PENDING_PATH);
	return 0;
}

static void tree_sync_report_error(const char *phase,
				   const struct tree_operation *op, int ret)
{
	int err;

	if (ret > 0) {
		if (op)
			pr_err("bpm tree sync: phase=%s seq=%lld id=%s rc=%d "
			       "(command status)", phase, (__s64)op->seq,
			       op->id, ret);
		else
			pr_err("bpm tree sync: phase=%s rc=%d (command status)",
			       phase, ret);
		return;
	}
	err = ret < 0 ? -ret : 0;

	if (op)
		pr_err("bpm tree sync: phase=%s seq=%lld id=%s rc=%d (%s)",
		       phase, (__s64)op->seq, op->id, ret,
		       err ? strerror(err) : "success");
	else
		pr_err("bpm tree sync: phase=%s rc=%d (%s)", phase, ret,
		       err ? strerror(err) : "success");
}

/*
 * The publication reference names, a tag or a manifest digest, signed and
 * with what tree sync checks before it applies anything.
 */
static int tree_fetch_checked(struct tree_source *src, const char *reference,
			      struct tree_publication *pub,
			      char *manifest_digest, size_t digest_sz)
{
	int bad_op, ret;

	ret = bpm_tree_fetch_publication(&src->c, src->repository, reference,
					 get_cert_path(), src->trusted, pub,
					 manifest_digest, digest_sz);
	if (ret)
		return ret;
	ret = tree_publication_verify(pub, &bad_op);
	if (ret && bad_op >= 0)
		tree_sync_report_error("operation_validate",
				       &pub->operations[bad_op], ret);
	return ret;
}

/*
 * A segment the walk back passed: the forward pass fetches it again by
 * its manifest digest, which names the same bytes, so only this is kept
 * and not the document.
 */
struct tree_segment {
	__u8 manifest_digest[32];
	__s64 base_seq;
	__s64 head_seq;
	__s64 generation;
};

/* The segments of a walk, newest first. */
struct tree_walk {
	struct tree_segment *segments;
	size_t n;
	size_t cap;
};

static void tree_walk_free(struct tree_walk *w)
{
	xfree(w->segments, w->cap * sizeof(*w->segments));
	*w = (struct tree_walk){};
}

static int tree_walk_add(struct tree_walk *w, const struct tree_publication *pub,
			 const char *manifest_digest)
{
	struct tree_segment *seg;

	if (w->n == w->cap) {
		size_t cap = w->cap ? 2 * w->cap : 8;

		seg = xreallocarray(w->segments, w->cap, cap, sizeof(*seg));
		if (!seg)
			return -ENOMEM;
		w->segments = seg;
		w->cap = cap;
	}
	seg = &w->segments[w->n];
	if (sha256_digest_decode(manifest_digest, seg->manifest_digest))
		return -EINVAL;
	seg->base_seq = pub->base_seq;
	seg->head_seq = pub->head_seq;
	seg->generation = pub->generation;
	w->n++;
	return 0;
}

/*
 * Back from the publication the tag names to the segment the cursor
 * last_seq lies in, each sealed segment fetched by the digest its
 * successor names and checked as the one it names. Nothing is applied
 * before the whole chain is known, and a gap, a fork or a walk past its
 * limit refuses the sync.
 */
static int tree_walk_back(struct tree_source *src,
			  const struct tree_publication *tag,
			  const char *tag_digest, __s64 last_seq,
			  struct tree_walk *w)
{
	const struct tree_publication *succ = tag;
	struct tree_publication fetched[2] = {};
	char digest[BPM_MAX_DIGEST];
	int next = 0, ret;

	ret = tree_walk_add(w, tag, tag_digest);
	while (!ret && succ->base_seq > last_seq) {
		ret = tree_walk_within(succ->base_seq, last_seq);
		if (ret) {
			pr_err("bpm tree sync: the segment that starts after seq %lld is more than %d operations past seq %lld, where this node is",
			       succ->base_seq,
			       last_seq ? TREE_MAX_WALK_OPS : TREE_MAX_JOIN_OPS,
			       last_seq);
			tree_sync_report_error("segment_walk", NULL, ret);
			break;
		}
		tree_publication_free(&fetched[next]);
		ret = tree_fetch_checked(src, succ->segment_manifest_digest,
					 &fetched[next], digest, sizeof(digest));
		if (ret) {
			pr_err("bpm tree sync: the sealed segment %s, which ends at seq %lld, cannot be fetched or does not verify",
			       succ->segment_manifest_digest, succ->base_seq);
			tree_sync_report_error("segment_fetch", NULL, ret);
			break;
		}
		ret = tree_segment_precedes(&fetched[next], digest, succ);
		if (ret) {
			pr_err("bpm tree sync: the sealed segment %s is not the one before the segment that starts after seq %lld",
			       succ->segment_manifest_digest, succ->base_seq);
			tree_sync_report_error("segment_chain", NULL, ret);
			break;
		}
		ret = tree_walk_add(w, &fetched[next], digest);
		succ = &fetched[next];
		next ^= 1;
	}
	tree_publication_free(&fetched[0]);
	tree_publication_free(&fetched[1]);
	return ret;
}

struct tree_sync {
	struct tree_state state;
	bool have_state;
	/* The history root at state.last_seq. */
	__u8 history_root[32];
	bool dry_run;
	/* The cursor a dry run reports, which it moves in memory alone. */
	__s64 dry_seq;
	int selected, skipped, applied, module_skipped;
};

/*
 * Acceptance steps 4 and 5: the segment starts where this node's history
 * was at its base, and its operations up to the cursor are the ones the
 * node processed, so a registry that serves another history than the one
 * the node went through is refused, inside a segment as at its base.
 */
static int tree_history_check(const struct tree_publication *pub,
			      const struct tree_sync *sync)
{
	__u8 projection_root[32], node[32], doc[32];
	__s64 last_seq = sync->state.last_seq;
	int ret = 0;

	if (pub->base_seq == last_seq)
		memcpy(node, sync->history_root, sizeof(node));
	else
		ret = tree_outcomes_read(pub->base_seq, pub->base_seq, NULL,
					 projection_root, node);
	if (!ret)
		ret = tree_history_at(pub, pub->base_seq, doc);
	if (!ret && memcmp(node, doc, sizeof(doc)))
		ret = -EKEYREJECTED;
	if (ret) {
		pr_err("bpm tree sync: the segment that starts after seq %lld does not start from this node's history there",
		       pub->base_seq);
		tree_sync_report_error("history_base", NULL, ret);
		return ret;
	}
	ret = tree_history_at(pub, last_seq, doc);
	if (!ret && memcmp(sync->history_root, doc, sizeof(doc)))
		ret = -EKEYREJECTED;
	if (ret) {
		pr_err("bpm tree sync: the operations of the publication up to seq %lld are not the ones this node processed",
		       last_seq);
		tree_sync_report_error("history_prefix", NULL, ret);
	}
	return ret;
}

/*
 * Recorded before its first operation is processed, so that a sync that
 * stops among them leaves the cursor within the publication the state
 * names.
 */
static int tree_record(struct tree_sync *sync,
		       const struct tree_publication *pub,
		       const char *manifest_digest)
{
	struct tree_state *st = &sync->state;
	int ret;

	st->generation = pub->generation;
	bpm_copy_string(st->manifest_digest, sizeof(st->manifest_digest),
			manifest_digest);
	st->head_seq = pub->head_seq;
	st->segment_base_seq = pub->base_seq;
	sync->have_state = true;
	if (sync->dry_run)
		return 0;
	ret = tree_state_write(st);
	if (ret)
		tree_sync_report_error("tree_state_commit_accept", NULL, ret);
	return ret;
}

/* A dry run moves its cursor in memory alone, for a walk to go on. */
static int tree_dry_pass(struct tree_sync *sync,
			 const struct tree_operation *op)
{
	__u8 digest[32];

	if (sha256_digest_decode(op->operation_digest, digest))
		return -EINVAL;
	sync->state.last_seq = op->seq;
	return chain_history_step(sync->history_root, digest,
				  sync->history_root);
}

static int tree_apply_operations(struct tree_sync *sync,
				 struct tree_publication *pub)
{
	struct tree_state *st = &sync->state;
	__u8 root[32];
	int ret;

	if (hex_decode(st->projection_root, root, sizeof(root))) {
		tree_sync_report_error("projection_root_decode", NULL, -EINVAL);
		return -EINVAL;
	}
	for (int i = 0; i < pub->n_operations; i++) {
		struct tree_operation *op = &pub->operations[i];
		__u8 digest[32], next[32];
		char artifact[PATH_MAX];
		bool skipped_module = false;

		if (op->seq <= st->last_seq)
			continue;
		ret = tree_selector_matches(&op->selector);
		if (ret < 0) {
			tree_sync_report_error("selector_evaluate", op, ret);
			return ret;
		}
		if (ret)
			sync->selected++;
		else
			sync->skipped++;
		if (sync->dry_run) {
			ret = tree_dry_pass(sync, op);
			if (ret)
				return ret;
			continue;
		}
		if (!ret) {
			ret = tree_outcome_unmatched(op, root,
						     sync->history_root);
			if (ret) {
				tree_sync_report_error("tree_outcome_append", op, ret);
				return ret;
			}
			st->last_seq = op->seq;
			continue;
		}
		ret = sha256_digest_decode(op->operation_digest, digest);
		if (ret) {
			tree_sync_report_error("operation_digest_parse", op, ret);
			return -EINVAL;
		}
		ret = tree_pending_write(op);
		if (ret) {
			tree_sync_report_error("pending_write", op, ret);
			return ret;
		}
		ret = tree_pull_artifact(op, artifact, sizeof(artifact));
		if (ret) {
			tree_sync_report_error("artifact_fetch_or_verify", op, ret);
			return ret;
		}
		if (!strcmp(op->op, "add"))
			ret = upatch_install(artifact);
		else if (!strcmp(op->op, "delete"))
			ret = upatch_remove(artifact);
		else
			return -EINVAL;
		if (ret == UPATCH_INSTALL_TARGET_MISSING &&
		    !strcmp(op->op, "add")) {
			skipped_module = true;
			ret = 0;
			sync->module_skipped++;
			pr_warn("bpm tree: skipped %s: module not loaded", op->id);
		}
		if (ret) {
			tree_sync_report_error("upatch_install", op, ret);
			return ret;
		}
		ret = sha256_2(root, 32, digest, 32, next);
		if (ret) {
			tree_sync_report_error("projection_root_hash", op, ret);
			return ret;
		}
		ret = tree_measure_operation(op, digest);
		if (ret) {
			tree_sync_report_error("register_extend", op, ret);
			return ret;
		}
		memcpy(root, next, sizeof(root));
		hex_encode(next, 32, st->projection_root);
		hex_encode(next, 32, st->projection_root_tpm);
		ret = tree_event_append(op->seq, op->operation_digest, next);
		if (ret) {
			tree_sync_report_error("tree_event_append", op, ret);
			return ret;
		}
		ret = tree_outcome_record(op->seq, digest,
					  skipped_module ?
					  TREE_OUTCOME_MODULE_ABSENT :
					  TREE_OUTCOME_APPLIED,
					  next, sync->history_root);
		if (ret) {
			tree_sync_report_error("tree_outcome_append", op, ret);
			return ret;
		}
		st->last_seq = op->seq;
		sync->applied++;
		ret = tree_state_write(st);
		if (ret) {
			tree_sync_report_error("tree_state_commit", op, ret);
			return ret;
		}
		ret = tree_status_update(op->id, skipped_module);
		if (ret) {
			tree_sync_report_error("tree_status_write", op, ret);
			return ret;
		}
		unlink(BPM_TREE_PENDING_PATH);
	}
	return 0;
}

/*
 * Acceptance steps 4 to 6 and the operations of one segment, the oldest
 * of a walk first, or of the one publication without a walk. Only the
 * oldest has an operation left pending: the node records a segment
 * before it processes any, so the state names the segment that operation
 * is in, and the walk starts from that one.
 */
static int tree_apply_segment(struct tree_sync *sync,
			      struct tree_publication *pub,
			      const char *manifest_digest, bool oldest)
{
	int ret;

	ret = tree_publication_follows(pub, sync->have_state ?
					    &sync->state : NULL,
				       manifest_digest);
	if (ret) {
		ret = ret < 0 ? ret : -ERANGE;
		pr_err("bpm tree sync: the segment %s does not follow seq %lld, where this node is",
		       manifest_digest, sync->state.last_seq);
		tree_sync_report_error("segment_chain", NULL, ret);
		return ret;
	}
	ret = tree_history_check(pub, sync);
	if (ret)
		return ret;
	if (oldest) {
		ret = tree_recover_pending(pub, &sync->state,
					   sync->history_root);
		if (ret) {
			tree_sync_report_error("pending_recovery", NULL, ret);
			return ret;
		}
		sync->dry_seq = sync->state.last_seq;
	}
	ret = tree_record(sync, pub, manifest_digest);
	if (ret)
		return ret;
	return tree_apply_operations(sync, pub);
}

/*
 * The walk forwards, oldest segment first: each sealed one fetched again
 * by its digest and checked as before, and the tag's document, which the
 * walk holds, last.
 */
static int tree_walk_forward(struct tree_source *src, struct tree_sync *sync,
			     const struct tree_walk *w,
			     struct tree_publication *tag,
			     const char *tag_digest)
{
	char want[BPM_MAX_DIGEST], digest[BPM_MAX_DIGEST];
	__u8 got[32];
	int ret;

	for (size_t i = w->n; i-- > 1;) {
		struct tree_publication seg = {};

		sha256_digest_encode(w->segments[i].manifest_digest, want);
		ret = tree_fetch_checked(src, want, &seg, digest,
					 sizeof(digest));
		if (!ret && (sha256_digest_decode(digest, got) ||
			     memcmp(got, w->segments[i].manifest_digest,
				    sizeof(got))))
			ret = -ERANGE;
		if (ret) {
			pr_err("bpm tree sync: the sealed segment %s, which ends at seq %lld, cannot be fetched again or has changed",
			       want, w->segments[i].head_seq);
			tree_sync_report_error("segment_fetch", NULL, ret);
		} else {
			ret = tree_apply_segment(sync, &seg, digest,
						 i == w->n - 1);
		}
		tree_publication_free(&seg);
		if (ret)
			return ret;
	}
	return tree_apply_segment(sync, tag, tag_digest, w->n == 1);
}

static int cmd_bpm_tree_sync(bool dry_run, const char *report_path)
{
	struct tree_source src = {};
	struct tree_walk walk = {};
	struct tree_sync sync = { .dry_run = dry_run };
	struct bpm_tree_config cfg;
	struct tree_publication pub = {};
	char manifest_digest[BPM_MAX_DIGEST];
	char report[PATH_MAX] = {};
	int ret;

	if (report_path && strscpy(report, report_path, sizeof(report)) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = load_tree_config(&cfg);
	/* Optional integration: manual `shirudo upatch` remains valid. */
	if (ret == -ENOENT) {
		ret = 0;
		goto out;
	}
	if (ret)
		goto out;
	ret = tree_state_read(&sync.state);
	if (!ret)
		sync.have_state = true;
	else if (ret != -ENOENT)
		goto out;
	ret = tree_source_open(&cfg, &src);
	if (ret)
		goto out;
	ret = tree_fetch_checked(&src, cfg.reference, &pub, manifest_digest,
				 sizeof(manifest_digest));
	if (ret)
		goto out;
	ret = tree_publication_follows(&pub, sync.have_state ?
					     &sync.state : NULL,
				       manifest_digest);
	if (ret < 0)
		goto out;
	if (!sync.have_state) {
		sync.state.schema = 1;
		bpm_copy_string(sync.state.tree_id, sizeof(sync.state.tree_id),
				pub.tree_id);
		memset(sync.state.projection_root, '0', 64);
		sync.state.projection_root[64] = '\0';
		memset(sync.state.projection_root_tpm, '0', 64);
		sync.state.projection_root_tpm[64] = '\0';
	}
	ret = tree_outcomes_resume(sync.state.last_seq, sync.history_root);
	if (ret) {
		tree_sync_report_error("outcomes_check", NULL, ret);
		goto out;
	}
	ret = tree_walk_back(&src, &pub, manifest_digest, sync.state.last_seq,
			     &walk);
	if (ret)
		goto out;
	ret = tree_walk_forward(&src, &sync, &walk, &pub, manifest_digest);
	if (ret)
		goto out;
	/* A run of operations without a match at the end moved the cursor. */
	if (!sync.dry_run) {
		ret = tree_state_write(&sync.state);
		if (ret) {
			tree_sync_report_error("tree_state_commit_final", NULL, ret);
			goto out;
		}
	} else {
		sync.state.last_seq = sync.dry_seq;
	}
	/* "-" is standard output, where the report goes without --report. */
	ret = tree_write_report(report[0] && strcmp(report, "-") ? report : NULL,
				&sync.state, sync.selected, sync.skipped,
				sync.applied, sync.module_skipped,
				sync.dry_run, chain_bound());
out:
	tree_walk_free(&walk);
	tree_publication_free(&pub);
	tree_source_clear(&src);
	return ret;
}

static int remove_tree_entry(const char *path, const struct stat *st,
			     int type, struct FTW *ftw)
{
	if (type == FTW_DP || type == FTW_D)
		return rmdir(path) ? -1 : 0;
	return unlink(path) ? -1 : 0;
}

static int remove_tree(const char *path)
{
	if (nftw(path, remove_tree_entry, 32, FTW_DEPTH | FTW_PHYS))
		return errno ? -errno : -EIO;
	return 0;
}

static int path_compare_desc(const void *left, const void *right)
{
	return strcmp(right, left);
}

/*
 * Detach a package's upatches through the signed unload directives it
 * shipped, in reverse name order, then remove the package tree. The
 * caller drops the state entry only after this succeeded, so a failed
 * detach leaves the package listed and loadable again.
 */
static int package_uninstall(const struct bpm_state_entry *st)
{
	char dir[PATH_MAX], updir[PATH_MAX];
	char (*unloads)[PATH_MAX];
	struct dirent *de;
	int n = 0, ret = 0;
	DIR *d;

	if (strsprintf(updir, sizeof(updir), "%s/upatches", st->path) < 0)
		return -ENAMETOOLONG;
	unloads = xcalloc(128, PATH_MAX);
	if (!unloads)
		return -ENOMEM;
	/*
	 * A tree already gone, from an uninstall that died before it
	 * wrote the state, leaves nothing to unload: the retry converges.
	 */
	d = opendir(updir);
	if (!d && errno != ENOENT) {
		ret = -errno;
		goto out;
	}
	while (d && (de = readdir(d))) {
		if (bpm_upatch_member(de->d_name, strlen(de->d_name)) !=
		    BPM_UPATCH_UNLOAD)
			continue;
		if (n >= 128) {
			ret = -E2BIG;
			break;
		}
		if (strsprintf(unloads[n], PATH_MAX, "%s/%s", updir, de->d_name) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		n++;
	}
	if (d)
		closedir(d);
	if (ret)
		goto out;
	qsort(unloads, (size_t)n, PATH_MAX, path_compare_desc);
	for (int i = 0; i < n; i++) {
		if (upatch_remove(unloads[i])) {
			pr_err("bpm uninstall: unload %s failed", unloads[i]);
			ret = -EIO;
			goto out;
		}
	}
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPM_PACKAGES_DIR,
		       st->name) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = remove_tree(dir);
	if (ret == -ENOENT)
		ret = 0;
out:
	xfree(unloads, 128 * PATH_MAX);
	return ret;
}

static const struct help_item bpm_subcmds[] = {
	{ "config", "manage package inputs and OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize or publish the signed upatch tree" },
	{ "key", "add, fingerprint, and list package certificates" },
	{ "pull", "download an OCI package into the current directory" },
	{ "info", "print a local or OCI package README" },
	{ "push", "publish an OCI package and its signed index entry" },
	{ "build", "build a signed OCI package from a Beefile" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
	{ "list", "list installed packages" },
	{ "uninstall", "unload and remove an installed package" },
};

static const struct help_item bpm_target_subcmds[] = {
	{ "config", "register and manage OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize the optional signed upatch tree" },
	{ "key", "add, fingerprint, and list package certificates" },
	{ "pull", "download an OCI package into the current directory" },
	{ "info", "print a local or OCI package README" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
	{ "list", "list installed packages" },
	{ "uninstall", "unload and remove an installed package" },
};

/*
 * Operator-only subcommands live in shirudo-build; hand the bpm argument
 * vector over unchanged so the helper parses it itself.
 */
static int bpm_exec_operator(const char *sub, int argc, const char **argv)
{
	char label[64];

	if (strsprintf(label, sizeof(label), "bpm %s", sub) < 0)
		return bpm_fail(sub, -E2BIG);
	return build_forward(label, (const char *const[]){ "bpm", sub, NULL },
			     argc - 2, argv + 2);
}

static const struct help bpm_target_help = {
	.usage = "shirudo bpm <config|repo|tree|key|pull|info|install|upgrade|list|uninstall>",
	.summary = "Manage signed target-local BPM packages backed by OCI repositories.",
	.sections = (const struct help_section[]) {
		HELP_ITEMS("subcommands:", bpm_target_subcmds),
	},
	.n_sections = 1,
};

static const struct help bpm_operator_help = {
	.usage = "shirudo bpm <config|repo|tree|key|pull|info|push|build|install|upgrade|list|uninstall>",
	.summary = "Manage signed OCI packages and publish packages from the operator.",
	.sections = (const struct help_section[]) {
		HELP_ITEMS("subcommands:", bpm_subcmds),
	},
	.n_sections = 1,
};

static int bpm_finish(int lock, int ret, const char *action)
{
	if (lock >= 0) {
		flock(lock, LOCK_UN);
		close(lock);
	}
	curl_global_cleanup();
	return ret ? bpm_fail(action, ret) : 0;
}

static const struct help_item bpm_key_subcmds[] = {
	{ "add", "install a trusted package certificate and print its fingerprint" },
	{ "fingerprint", "print the SHA-256 fingerprint of a certificate's SPKI" },
	{ "list", "list installed certificate fingerprints" },
};

enum bpm_key_list_opt {
	KEY_LIST_JSON,
};

static const struct opt_spec bpm_key_list_opts[] = {
	[KEY_LIST_JSON] = { "--json", 0, 0, NULL,
		"print the certificates as JSON" },
};

static const struct help_section bpm_key_sections[] = {
	HELP_ITEMS("subcommands:", bpm_key_subcmds),
	HELP_OPTIONS("list options:", bpm_key_list_opts),
};

static const struct help bpm_key_help = {
	.usage = "shirudo bpm key <add|fingerprint|list>",
	.summary = "Manage package signing certificates.",
	.sections = bpm_key_sections,
	.n_sections = ARRAY_SIZE(bpm_key_sections),
	.footer = "add and fingerprint accept a certificate file, .bee package, or\n"
		  "oci://registry/repository:tag. list reads /var/lib/shirudo/keys.\n"
		  "Examples:\n"
		  "  shirudo bpm key fingerprint ./package.bee\n"
		  "  shirudo bpm key add oci://quay.io/namespace/package:tag\n"
		  "  shirudo bpm key list",
};

static int cmd_bpm_key(int argc, const char **argv)
{
	size_t len = 0, cap = 0, n;
	const char *sub, *source;
	struct opt_parser p;
	__u8 *der = NULL;
	char hex[65];
	int ret;

	if (argc < 2 || is_help(argv[1])) {
		print_help(&bpm_key_help);
		return argc < 2 ? 2 : 0;
	}
	if (is_list_cmds(argv[1])) {
		print_subcmd_list(bpm_key_subcmds,
				  ARRAY_SIZE(bpm_key_subcmds));
		return 0;
	}
	sub = resolve_subcommand("bpm key", argv[1], bpm_key_subcmds,
				 ARRAY_SIZE(bpm_key_subcmds));
	if (!sub)
		return 2;
	if (!strcmp(sub, "list")) {
		OPT_INIT(&p, "bpm key list", bpm_key_list_opts, &bpm_key_help,
			 argc, argv, 2);
		ret = bpm_args(&p, NULL, NULL, 0, 0, NULL, &n);
		if (ret != OPT_END)
			return bpm_exit(ret);
		ret = list_keys(opt_given(&p, KEY_LIST_JSON));
		return ret ? bpm_fail("key list", ret) : 0;
	}
	opt_init(&p, !strcmp(sub, "add") ? "bpm key add" : "bpm key fingerprint",
		 NULL, 0, &bpm_key_help, argc, argv, 2);
	ret = bpm_args(&p, NULL, &source, 1, 1,
		       "a certificate, a .bee package or an oci:// reference",
		       &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	if (!strcmp(sub, "add") && image_config_active()) {
		pr_err("image mode: add vouched BPF signers to the signed "
		       "config selected for boot and reboot to enroll them");
		return 1;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	ret = key_source_read(source, &der, &len, &cap);
	if (!ret) {
		ret = key_fingerprint(der, len, hex);
		if (!ret && !strcmp(sub, "add"))
			ret = install_key(der, len);
		if (!ret)
			puts(hex);
		xfree(der, cap);
	}
	return bpm_finish(-1, ret, !strcmp(sub, "add") ?
			  "key add" : "key fingerprint");
}

/* The package index and the state take over a MiB between them. */
struct bpm_tables {
	struct bpm_index_entry	entries[BPM_MAX_ENTRIES];
	struct bpm_state_entry	state[BPM_MAX_STATE];
};

static int with_tables(int (*fn)(const char *, struct bpm_tables *),
		       const char *arg, const char *what)
{
	struct bpm_tables *t;
	int ret;

	t = xcalloc(1, sizeof(*t));
	if (!t)
		return bpm_fail(what, -ENOMEM);
	ret = fn(arg, t);
	xfree(t, sizeof(*t));
	return ret;
}

static int bpm_install(const char *ref, struct bpm_tables *t)
{
	char source[BPM_MAX_NAME], name[BPM_MAX_NAME], version[BPM_MAX_NAME];
	struct bpm_index_entry *entries = t->entries;
	struct bpm_state_entry *state = t->state;
	bool direct = str_has_prefix(ref, "oci://");
	struct bpm_index_entry selected;
	struct bpm_source source_cfg;
	int n_entries, n_state, lock, ret, i;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	lock = with_bpm_lock();
	if (lock < 0)
		return bpm_finish(-1, lock, "lock");
	if (direct) {
		ret = prepare_direct_install(ref, &source_cfg, &selected);
	} else {
		ret = parse_package_ref(ref, source, sizeof(source), name,
					sizeof(name), version, sizeof(version));
	}
	if (!ret)
		ret = bpm_state_read(state, &n_state);
	if (ret)
		return bpm_finish(lock, ret, "install");
	for (i = 0; i < n_state; i++) {
		if (!strcmp(state[i].name, direct ? selected.name : name))
			/*
			 * Installation is idempotent by package name.
			 * This also avoids contacting the repository
			 * for a package that is already active.  Use
			 * `bpm upgrade` to change versions.
			 */
			return bpm_finish(lock, 0, "install");
	}
	if (!direct) {
		ret = load_source(source, &source_cfg);
		if (!ret)
			ret = load_cached_index(&source_cfg, entries, &n_entries);
		if (!ret)
			ret = find_entry(entries, n_entries, name,
					 version[0] ? version : NULL, &selected);
	}
	if (ret)
		return bpm_finish(lock, ret, "install");
	if (n_state >= BPM_MAX_STATE)
		return bpm_finish(lock, -E2BIG, "install");
	ret = package_install(&source_cfg, &selected, NULL, NULL);
	if (ret)
		return bpm_finish(lock, ret, "install");
	bpm_copy_string(state[n_state].name, sizeof(state[n_state].name),
			direct ? selected.name : name);
	bpm_copy_string(state[n_state].version, sizeof(state[n_state].version),
			selected.version);
	bpm_copy_string(state[n_state].source, sizeof(state[n_state].source),
			direct ? "direct" : source);
	if (strsprintf(state[n_state].path, sizeof(state[n_state].path),
		       "%s/%s/%s", BPM_PACKAGES_DIR,
		       direct ? selected.name : name,
		       selected.version) < 0)
		return bpm_finish(lock, -ENAMETOOLONG, "install");
	ret = bpm_state_write(state, n_state + 1);
	if (ret) {
		/* Unlisted, the package could never be removed. */
		if (package_uninstall(&state[n_state]))
			pr_err("bpm install: %s stays installed but "
			       "unlisted", state[n_state].name);
		else
			pr_err("bpm install: %s removed again, the "
			       "state could not be written",
			       state[n_state].name);
	}
	return bpm_finish(lock, ret, "write state");
}

static int bpm_upgrade(const char *unused, struct bpm_tables *t)
{
	struct bpm_state_entry *state = t->state;
	int n_state, lock, ret, wrc, i;
	bool source_failed = false;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	lock = with_bpm_lock();
	if (lock < 0)
		return bpm_finish(-1, lock, "lock");
	ret = bpm_state_read(state, &n_state);
	if (ret)
		return bpm_finish(lock, ret, "read state");
	for (i = 0; i < n_state; i++) {
		struct bpm_index_entry *entries = t->entries, selected;
		struct bpm_source source_cfg;
		char path[PATH_MAX];
		int n_entries;

		if (!strcmp(state[i].source, "direct"))
			continue;
		ret = load_source(state[i].source, &source_cfg);
		if (!ret)
			ret = load_cached_index(&source_cfg, entries, &n_entries);
		if (ret > 0) {
			source_failed = true;
			ret = 0;
			continue;
		}
		if (!ret)
			ret = find_entry(entries, n_entries, state[i].name, NULL,
					 &selected);
		if (ret == -ENOENT) {
			ret = 0;
			continue;
		}
		if (ret)
			break;
		if (bpm_semver_compare(selected.version, state[i].version) <= 0)
			continue;
		ret = package_install(&source_cfg, &selected, state[i].path,
				      state[i].version);
		if (ret)
			break;
		bpm_copy_string(state[i].version, sizeof(state[i].version),
				selected.version);
		if (strsprintf(path, sizeof(path), "%s/%s/%s",
			       BPM_PACKAGES_DIR, state[i].name,
			       selected.version) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		bpm_copy_string(state[i].path, sizeof(state[i].path), path);
	}
	/* Packages upgraded before a failure stay on record. */
	wrc = bpm_state_write(state, n_state);
	if (ret)
		return bpm_finish(lock, ret, "upgrade");
	if (wrc)
		return bpm_finish(lock, wrc, "write state");
	return bpm_finish(lock, source_failed, "upgrade");
}

enum bpm_info_opt {
	INFO_ALL,
	INFO_JSON,
};

static const struct opt_spec bpm_info_opts[] = {
	[INFO_ALL] = { "--all", 0, 0, NULL,
		"with upatches: the .unload.upatch directives too" },
	[INFO_JSON] = { "--json", 0, 0, NULL,
		"with data: the decoded .rodata as JSON" },
};

static const struct help_section bpm_info_sections[] = {
	HELP_OPTIONS("options:", bpm_info_opts),
};

static const struct help bpm_info_help = {
	.usage	    = "shirudo bpm info <package-file|package-reference>\n"
		      "       shirudo bpm info upatches <package> [--all]\n"
		      "       shirudo bpm info data <package> <upatch-member> "
		      "[--json]",
	.summary    = "Print a package's README.md, list its upatches, or "
		      "decode the BPF\n.rodata initial data through its BTF "
		      "types. A package is a local .bee\nfile or an oci:// "
		      "reference.",
	.sections   = bpm_info_sections,
	.n_sections = ARRAY_SIZE(bpm_info_sections),
	.footer     = "Examples:\n"
		      "  shirudo bpm info ./package.bee\n"
		      "  shirudo bpm info upatches ./package.bee --all\n"
		      "  shirudo bpm info data ./package.bee "
		      "upatches/kernel-obs.upatch --json",
};

enum bpm_tree_sync_opt {
	TREE_SYNC_DRY_RUN,
	TREE_SYNC_REPORT,
};

static const struct opt_spec bpm_tree_sync_opts[] = {
	[TREE_SYNC_DRY_RUN] = { "--dry-run", 0, 0, NULL,
		"say what would change and change nothing" },
	[TREE_SYNC_REPORT] = { "--report", 0, 0, "<path>",
		"write the JSON report there" },
};

static const struct help_item bpm_tree_subcmds[] = {
	{ "sync", "apply the configured tree on a target" },
	{ "append", "publish a package's tree entries (operator)" },
	{ "show", "print a verified publication (operator)" },
};

static const struct help_section bpm_tree_sections[] = {
	HELP_ITEMS("subcommands:", bpm_tree_subcmds),
	HELP_OPTIONS("sync options:", bpm_tree_sync_opts),
};

static const struct help bpm_tree_help = {
	.usage	    = "shirudo bpm tree sync [--dry-run] [--report=<path>]\n"
		      "       shirudo bpm tree append <package-file> "
		      "<repository> [options]\n"
		      "       shirudo bpm tree show <repository> --cert <file> "
		      "[--reference <ref>] [--walk]",
	.summary    = "sync applies the configured tree on a target. append "
		      "and show are\noperator-only and run in shirudo-build: "
		      "append publishes the\n[upatches.tree] entries of a "
		      "built package as the next operations of the\nsigned "
		      "tree, show prints a verified publication; see their "
		      "--help where\nthe operator package is installed.",
	.sections   = bpm_tree_sections,
	.n_sections = ARRAY_SIZE(bpm_tree_sections),
};

static const struct help bpm_pull_help = {
	.usage	 = "shirudo bpm pull <package-reference>",
	.summary = "Download an OCI package into the current directory. The "
		   "reference\nstarts with oci://.",
	.footer	 = "Example:\n"
		   "  shirudo bpm pull oci://quay.io/namespace/package:tag",
};

static const struct help_item bpm_repo_subcmds[] = {
	{ "update", "refresh the signed index of a source, or of all" },
};

static const struct help_section bpm_repo_sections[] = {
	HELP_ITEMS("subcommands:", bpm_repo_subcmds),
};

static const struct help bpm_repo_help = {
	.usage	    = "shirudo bpm repo update [<source>]",
	.summary    = "Refresh the signed index of one registered source, or "
		      "of all of them.",
	.sections   = bpm_repo_sections,
	.n_sections = ARRAY_SIZE(bpm_repo_sections),
};

static const struct help bpm_install_help = {
	.usage	 = "shirudo bpm install <package>",
	.summary = "Download and activate a repository or OCI package.",
};

enum bpm_list_opt {
	LIST_JSON,
};

static const struct opt_spec bpm_list_opts[] = {
	[LIST_JSON] = { "--json", 0, 0, NULL,
		"print the installed packages as JSON" },
};

static const struct help_section bpm_list_sections[] = {
	HELP_OPTIONS("options:", bpm_list_opts),
};

static const struct help bpm_list_help = {
	.usage	    = "shirudo bpm list [--json]",
	.summary    = "List the installed packages.",
	.sections   = bpm_list_sections,
	.n_sections = ARRAY_SIZE(bpm_list_sections),
};

static const struct help bpm_uninstall_help = {
	.usage	 = "shirudo bpm uninstall <package>",
	.summary = "Unload and remove an installed package.",
};

static const struct help bpm_upgrade_help = {
	.usage	 = "shirudo bpm upgrade",
	.summary = "Activate the newer package versions the cached indexes "
		   "offer.",
};

enum bpm_info_show {
	INFO_SHOW_README,	/* <package> */
	INFO_SHOW_UPATCHES,	/* upatches <package> */
	INFO_SHOW_DATA,		/* data <package> <upatch-member> */
};

static enum bpm_info_show bpm_info_show(const char *word)
{
	if (!strcmp(word, "upatches"))
		return INFO_SHOW_UPATCHES;
	if (!strcmp(word, "data"))
		return INFO_SHOW_DATA;
	return INFO_SHOW_README;
}

/* Whether the words and options of bpm info go together, saying why not. */
static bool bpm_info_usage_ok(const struct opt_parser *p,
			      enum bpm_info_show show, const char **args,
			      size_t n)
{
	if (show == INFO_SHOW_UPATCHES && n != 2)
		opt_usage(p, "upatches takes <package>");
	else if (show == INFO_SHOW_DATA && n != 3)
		opt_usage(p, "data takes <package> <upatch-member>");
	else if (show == INFO_SHOW_README && n != 1)
		opt_usage(p, "unexpected argument '%s'", args[1]);
	else if (opt_given(p, INFO_ALL) && show != INFO_SHOW_UPATCHES)
		opt_usage(p, "--all goes with upatches alone");
	else if (opt_given(p, INFO_JSON) && show != INFO_SHOW_DATA)
		opt_usage(p, "--json goes with data alone");
	else
		return true;
	return false;
}

static int bpm_info_cmd(int argc, const char **argv)
{
	const char *args[3] = {};
	enum bpm_info_show show;
	struct opt_parser p;
	size_t n;
	int ret;

	OPT_INIT(&p, "bpm info", bpm_info_opts, &bpm_info_help, argc, argv, 2);
	ret = bpm_args(&p, NULL, args, 1, 3, "a package", &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	show = bpm_info_show(args[0]);
	if (!bpm_info_usage_ok(&p, show, args, n))
		return EXIT_USAGE;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	switch (show) {
	case INFO_SHOW_UPATCHES:
		ret = print_package_upatches(args[1],
					     opt_given(&p, INFO_ALL));
		break;
	case INFO_SHOW_DATA:
		ret = print_package_upatch_data(args[1], args[2],
						opt_given(&p, INFO_JSON));
		break;
	default:
		ret = print_package_readme(args[0]);
		break;
	}
	return bpm_finish(-1, ret, "info");
}

static int bpm_tree_cmd(int argc, const char **argv)
{
	const char *values[ARRAY_SIZE(bpm_tree_sync_opts)] = {};
	struct opt_parser p;
	int lock, ret;
	size_t n;

	if (argc < 3 || is_help(argv[2])) {
		print_help(&bpm_tree_help);
		return argc < 3 ? EXIT_USAGE : 0;
	}
	if (is_list_cmds(argv[2])) {
		print_subcmd_list(bpm_tree_subcmds, ARRAY_SIZE(bpm_tree_subcmds));
		return 0;
	}
	if (!strcmp(argv[2], "append") || !strcmp(argv[2], "show"))
		return bpm_exec_operator("tree", argc, argv);
	if (strcmp(argv[2], "sync")) {
		pr_err("bpm tree: '%s' is not a subcommand", argv[2]);
		return EXIT_USAGE;
	}
	OPT_INIT(&p, "bpm tree sync", bpm_tree_sync_opts, &bpm_tree_help, argc,
		 argv, 3);
	ret = bpm_args(&p, values, NULL, 0, 0, NULL, &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	/*
	 * The tree is optional. Avoid taking the BPM lock (and avoid
	 * requiring writable state directories) when it is not configured.
	 */
	if (!tree_configured())
		return 0;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	lock = with_bpm_lock();
	if (lock < 0)
		return bpm_finish(-1, lock, "lock");
	ret = cmd_bpm_tree_sync(opt_given(&p, TREE_SYNC_DRY_RUN),
				values[TREE_SYNC_REPORT]);
	return bpm_finish(lock, ret, "tree sync");
}

static int bpm_pull_cmd(int argc, const char **argv)
{
	struct opt_parser p;
	const char *ref;
	size_t n;
	int ret;

	opt_init(&p, "bpm pull", NULL, 0, &bpm_pull_help, argc, argv, 2);
	ret = bpm_args(&p, NULL, &ref, 1, 1,
		       "a package reference starting with oci://, such as "
		       "oci://quay.io/namespace/package:tag", &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	return bpm_finish(-1, pull_package(ref), "pull");
}

static int bpm_repo_cmd(int argc, const char **argv)
{
	const char *named = NULL;
	struct opt_parser p;
	int lock, ret = 0;
	size_t n;

	if (argc < 3 || is_help(argv[2])) {
		print_help(&bpm_repo_help);
		return argc < 3 ? EXIT_USAGE : 0;
	}
	if (is_list_cmds(argv[2])) {
		print_subcmd_list(bpm_repo_subcmds, ARRAY_SIZE(bpm_repo_subcmds));
		return 0;
	}
	if (strcmp(argv[2], "update")) {
		pr_err("bpm repo: '%s' is not a subcommand", argv[2]);
		return EXIT_USAGE;
	}
	opt_init(&p, "bpm repo update", NULL, 0, &bpm_repo_help, argc, argv, 3);
	ret = bpm_args(&p, NULL, &named, 0, 1, NULL, &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	ret = 0;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	lock = with_bpm_lock();
	if (lock < 0)
		return bpm_finish(-1, lock, "lock");
	if (!named) {
		DIR *d = registries_opendir();
		struct dirent *entry;

		if (!d && errno != ENOENT)
			ret = -errno;
		/* One unreachable registry must not hold back the others. */
		while (d && (entry = readdir(d))) {
			size_t len = strlen(entry->d_name);
			char source[BPM_MAX_NAME];

			if (!name_has_suffix(entry->d_name, len, ".conf"))
				continue;
			if (strsprintf(source, sizeof(source), "%.*s",
				       (int)(len - 5), entry->d_name) < 0) {
				ret = -ENAMETOOLONG;
				continue;
			}
			if (repo_update_one(source))
				ret = -EIO;
		}
		if (d)
			closedir(d);
	} else {
		ret = repo_update_one(named);
	}
	return bpm_finish(lock, ret, "repo update");
}

static int bpm_install_cmd(int argc, const char **argv)
{
	struct opt_parser p;
	const char *package;
	size_t n;
	int ret;

	opt_init(&p, "bpm install", NULL, 0, &bpm_install_help, argc, argv, 2);
	ret = bpm_args(&p, NULL, &package, 1, 1, "<package>", &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	return with_tables(bpm_install, package, "install");
}

static int bpm_list_cmd(int argc, const char **argv)
{
	struct bpm_state_entry *state;
	struct opt_parser p;
	int n_state, ret;
	bool json;
	size_t n;

	OPT_INIT(&p, "bpm list", bpm_list_opts, &bpm_list_help, argc, argv, 2);
	ret = bpm_args(&p, NULL, NULL, 0, 0, NULL, &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	json = opt_given(&p, LIST_JSON);
	state = xcalloc(BPM_MAX_STATE, sizeof(*state));
	if (!state)
		return bpm_fail("list", -ENOMEM);
	ret = bpm_state_read(state, &n_state);
	if (!ret && json) {
		size_t cap = 256 + (size_t)n_state * 3 * BPM_MAX_NAME;
		char *buf = xmalloc(cap);
		struct json_emit e = { .buf = buf, .cap = cap };

		if (!buf) {
			ret = -ENOMEM;
		} else {
			json_obj_open(&e);
			json_kv_int(&e, "schema", 1);
			json_arr_open(&e, "packages");
			for (int i = 0; i < n_state; i++) {
				json_obj_open(&e);
				json_kv_string(&e, "name",
					       state[i].name);
				json_kv_string(&e, "version",
					       state[i].version);
				json_kv_string(&e, "source",
					       state[i].source);
				json_obj_close(&e);
			}
			json_arr_close(&e);
			json_obj_close(&e);
			if (e.err)
				ret = e.err;
			else
				puts(buf);
			xfree(buf, cap);
		}
	} else if (!ret) {
		size_t width = NAME_COLUMN_MIN;

		printf("Installed packages:\n");
		for (int i = 0; i < n_state; i++)
			width = max(width, strlen(state[i].name));
		if (!n_state)
			printf("  none\n");
		else
			printf("  %-*s  %-12s  %s\n", (int)width, "NAME",
			       "VERSION", "SOURCE");
		for (int i = 0; i < n_state; i++)
			printf("  %-*s  %-12s  %s\n", (int)width, state[i].name,
			       state[i].version, state[i].source);
	}
	xfree(state, BPM_MAX_STATE * sizeof(*state));
	return ret ? bpm_fail("list", ret) : 0;
}

static int bpm_uninstall_cmd(int argc, const char **argv)
{
	struct bpm_state_entry *state;
	int n_state, lock, ret, i;
	struct opt_parser p;
	const char *package;
	size_t n;

	opt_init(&p, "bpm uninstall", NULL, 0, &bpm_uninstall_help, argc, argv,
		 2);
	ret = bpm_args(&p, NULL, &package, 1, 1, "<package>", &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	if (!bpm_name_ok(package))
		return bpm_fail("uninstall", -EINVAL);
	state = xcalloc(BPM_MAX_STATE, sizeof(*state));
	if (!state)
		return bpm_fail("uninstall", -ENOMEM);
	lock = with_bpm_lock();
	if (lock < 0) {
		xfree(state, BPM_MAX_STATE * sizeof(*state));
		return bpm_finish(-1, lock, "lock");
	}
	ret = bpm_state_read(state, &n_state);
	for (i = 0; !ret && i < n_state; i++) {
		if (!strcmp(state[i].name, package))
			break;
	}
	if (!ret && i == n_state)
		ret = -ENOENT;
	if (!ret)
		ret = package_uninstall(&state[i]);
	if (!ret) {
		memmove(&state[i], &state[i + 1],
			(size_t)(n_state - i - 1) * sizeof(*state));
		ret = bpm_state_write(state, n_state - 1);
	}
	xfree(state, BPM_MAX_STATE * sizeof(*state));
	return bpm_finish(lock, ret, "uninstall");
}

static int bpm_upgrade_cmd(int argc, const char **argv)
{
	struct opt_parser p;
	size_t n;
	int ret;

	opt_init(&p, "bpm upgrade", NULL, 0, &bpm_upgrade_help, argc, argv, 2);
	ret = bpm_args(&p, NULL, NULL, 0, 0, NULL, &n);
	if (ret != OPT_END)
		return bpm_exit(ret);
	return with_tables(bpm_upgrade, NULL, "upgrade");
}

int cmd_bpm(int argc, const char **argv)
{
	const struct help *help = build_available() ?
		&bpm_operator_help : &bpm_target_help;
	const struct help_item *subcmds = build_available() ?
		bpm_subcmds : bpm_target_subcmds;
	size_t n_subcmds = build_available() ? ARRAY_SIZE(bpm_subcmds) :
		ARRAY_SIZE(bpm_target_subcmds);
	const char *sub;

	if (argc < 2 || is_help(argv[1])) {
		print_help(help);
		return argc < 2 ? EXIT_USAGE : 0;
	}
	if (is_list_cmds(argv[1])) {
		print_subcmd_list(subcmds, n_subcmds);
		return 0;
	}
	sub = resolve_subcommand("shirudo bpm", argv[1], subcmds,
				 n_subcmds);
	if (!sub)
		return EXIT_USAGE;
	if (!strcmp(sub, "config") && argc >= 3 &&
	    !strcmp(argv[2], "update"))
		return bpm_exec_operator("config", argc, argv);
	if (!strcmp(sub, "config"))
		return cmd_bpm_config(argc - 1, argv + 1);
	if (!strcmp(sub, "build") || !strcmp(sub, "push"))
		return bpm_exec_operator(sub, argc, argv);
	if (!strcmp(sub, "key"))
		return cmd_bpm_key(argc - 1, argv + 1);
	if (!strcmp(sub, "info"))
		return bpm_info_cmd(argc, argv);
	if (!strcmp(sub, "tree"))
		return bpm_tree_cmd(argc, argv);
	if (!strcmp(sub, "pull"))
		return bpm_pull_cmd(argc, argv);
	if (!strcmp(sub, "repo"))
		return bpm_repo_cmd(argc, argv);
	if (!strcmp(sub, "install"))
		return bpm_install_cmd(argc, argv);
	if (!strcmp(sub, "list"))
		return bpm_list_cmd(argc, argv);
	if (!strcmp(sub, "uninstall"))
		return bpm_uninstall_cmd(argc, argv);
	return bpm_upgrade_cmd(argc, argv);
}
