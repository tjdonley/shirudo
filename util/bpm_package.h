/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .bee archives, signed repository indexes and tree publications.
 */

#ifndef SHIRUDO_BPM_PACKAGE_H
#define SHIRUDO_BPM_PACKAGE_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "bpm_oci.h"
#include "bpm_tree.h"

struct trusted_set;

struct bpm_index_entry {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char repository[BPM_MAX_ENDPOINT];
	char manifest_digest[BPM_MAX_DIGEST];
	char package_digest[BPM_MAX_DIGEST];
	char signer[BPM_MAX_DIGEST];
	__s64 package_size;
};

struct bpm_package_info {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char signer[BPM_MAX_DIGEST];
	__u8 *cert;
	size_t cert_len;
};

int bpm_index_parse(const __u8 *body, size_t len,
		    struct bpm_index_entry *entries, int *n_entries);
/* The order of two package versions: below 0, 0 or above 0. */
int bpm_semver_compare(const char *a, const char *b);
/* Whether s is a SemVer 2.0.0 version, as bpm build takes alone. */
bool bpm_semver_valid(const char *s);
int bpm_verify_cms(const __u8 *payload, size_t payload_len,
		   const __u8 *sig, size_t sig_len,
		   const char *cert_path);

bool bpm_archive_rel_ok(const char *name);

enum bpm_upatch_member {
	BPM_UPATCH_OTHER,
	BPM_UPATCH_LOAD,
	BPM_UPATCH_UNLOAD,
};

/*
 * What a file of a package's upatches/ is by the len bytes of its name:
 * <x>.unload.upatch an unload directive, any other <x>.upatch a load,
 * and a hidden name neither.
 */
enum bpm_upatch_member bpm_upatch_member(const char *name, size_t len);

/*
 * The other half of a load or unload name, <x>.unload.upatch for
 * <x>.upatch and back, into the cap bytes at out: 0, -EINVAL for a name
 * that is neither, -ENAMETOOLONG when it does not fit.
 */
int bpm_upatch_pair(const char *name, size_t len, char *out, size_t cap);

typedef int (*bpm_pkg_member_fn)(void *ctx, const char *member, char type);

/*
 * Visit validated package-relative ustar members without extracting them,
 * reading the archive from the start of fd, which it leaves open.
 */
int bpm_pkg_visit_members_fd(int fd, const char *package_dir,
			     bpm_pkg_member_fn visit, void *ctx);

/*
 * Read one member of a gzip'd ustar .bee into an xmalloc'd buffer of
 * out_len + 1 bytes. member is relative to the single top-level package
 * directory; package_dir pins that directory when known, found_dir
 * reports it otherwise.
 */
int bpm_pkg_read_member_in(const char *archive, const char *member,
			   const char *package_dir, char *found_dir,
			   size_t found_dir_sz, __u8 **out,
			   size_t *out_len, size_t max);
int bpm_pkg_read_member_fd(int fd, const char *member,
			   const char *package_dir, char *found_dir,
			   size_t found_dir_sz, __u8 **out,
			   size_t *out_len, size_t max);
int bpm_pkg_read_member(const char *archive, const char *member,
			__u8 **out, size_t *out_len, size_t max);
/*
 * Unpack the regular files and directories under the single top-level
 * directory of a .bee into dest; anything else fails the archive.
 */
int bpm_pkg_extract(const char *archive, const char *dest);
int bpm_pkg_load_info(const char *archive, struct bpm_package_info *info);

/* Room for the manifest of a tree publication, in bytes. */
#define BPM_TREE_MANIFEST_CAP	8192u

/*
 * The manifest of a tree publication whose payload and signature are the
 * layers payload and sig, as bpm tree append writes it, into out of cap
 * bytes with its length in *len. 0 or -errno.
 */
int bpm_tree_manifest(const struct bpm_descriptor *payload,
		      const struct bpm_descriptor *sig, char *out, size_t cap,
		      size_t *len);

/*
 * Fetch the signed tree publication at repository:reference, check every
 * layer against its descriptor and the payload against trusted, or
 * cert_path when trusted is NULL, and
 * parse it. The manifest must be exactly bpm_tree_manifest() of its two
 * layers, -EBADMSG otherwise, so that the digest a node records and a
 * successor names follows from the signed layers alone. -ENOENT when the
 * reference does not exist yet.
 * bpm_tree_fetch_document() stops before the parse and hands over the
 * checked bytes, which the caller frees with bpm_buffer_free().
 */
int bpm_tree_fetch_document(struct bpm_oci_client *c,
			    const char *repository, const char *reference,
			    const char *cert_path,
			    const struct trusted_set *trusted,
			    struct bpm_buffer *payload,
			    char *manifest_digest, size_t digest_sz);
int bpm_tree_fetch_publication(struct bpm_oci_client *c,
			       const char *repository, const char *reference,
			       const char *cert_path,
			       const struct trusted_set *trusted,
			       struct tree_publication *pub,
			       char *manifest_digest, size_t digest_sz);

#endif /* SHIRUDO_BPM_PACKAGE_H */
