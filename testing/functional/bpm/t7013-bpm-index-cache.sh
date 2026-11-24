#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

command -v openssl >/dev/null || test_skip_all "no openssl"
command -v python3 >/dev/null || test_skip_all "no python3"
command -v bwrap >/dev/null || test_skip_all "no bwrap for isolated BPM state"
openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA' ||
	test_skip_all "openssl without ML-DSA (needs OpenSSL >= 3.5)"
H=${SHIRUDO_TEST_IMAGE_CLI_HELPER:-./helper/test-image-cli}
# CI links the helper against the OpenSSL built in this directory.
toolchain_build=$(cd .. && pwd)/build
if [ ! -x "$H" ]; then
	printf "not ok 1 - test-image-cli helper is required\n1..1\n"
	exit 1
fi
W=$(mktemp -d)
SERVER=
cleanup() {
	[ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || :
	rm -rf "$W"
}
trap cleanup EXIT

ROOT=$W/config
KEYS=$ROOT/etc/shirudo/bpm/keys
SOURCES=$ROOT/etc/shirudo/bpm/registries.d
STATE=$W/state/bpm
REPO=$W/registry/team/bpm-index
mkdir -p "$KEYS" "$SOURCES" "$STATE/repos/main" "$REPO/blobs" "$REPO/manifests"
touch "$ROOT/etc/shirudo/shirudo.conf"

# Root in this private filesystem owns the cache and every directory above it.
bpm() {
	bwrap --unshare-user --uid 0 --gid 0 --ro-bind /usr /usr \
		--ro-bind-try /lib /lib --ro-bind-try /lib64 /lib64 \
		--ro-bind-try "$toolchain_build" "$toolchain_build" \
		--dev /dev --proc /proc --bind "$W/state" /var/lib/shirudo \
		--ro-bind "$ROOT" /config --ro-bind "$H" /cli \
		/cli /config bpm "$@"
}
bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / true ||
	test_skip_all "unprivileged user namespaces unavailable"

for name in first next; do
	openssl req -x509 -newkey ML-DSA-87 -nodes -subj "/CN=$name" \
		-addext subjectKeyIdentifier=hash -keyout "$W/$name.key" \
		-outform DER -out "$W/$name.der" 2>"$W/openssl.log"
done
cp "$W/first.der" "$KEYS/current.der"
DUMMY=sha256:$(printf '%064d' 0)
printf '{"schema":1,"packages":[{"name":"probe","version":"2.0.0","repository":"team/probe","manifest_digest":"%s","package_digest":"%s","package_size":1}]}\n' \
	"$DUMMY" "$DUMMY" >"$W/index.json"

publish() {
	openssl cms -sign -binary -md sha512 -in "$W/index.json" \
		-signer "$W/$1.der" -inkey "$W/$1.key" -outform DER \
		-out "$W/index.sig" -nosmimecap -nocerts -keyid &&
	python3 - "$W" "$REPO" <<'PY'
import hashlib, json, pathlib, sys
work, repo = map(pathlib.Path, sys.argv[1:])
layers = []
for name, media in (("index.json", "application/vnd.shirudo.bpm.index.v1+json"),
                    ("index.sig", "application/vnd.shirudo.bpm.index.signature.v1")):
    body = (work / name).read_bytes()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    (repo / "blobs" / digest).write_bytes(body)
    layers.append({"digest": digest, "size": len(body), "mediaType": media})
(repo / "manifests/stable").write_text(json.dumps({"schemaVersion": 2, "layers": layers}))
PY
}
publish first
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 helper/test-oci-registry.py --root "$W/registry" --port "$PORT" \
	--log "$W/requests" --ready-file "$W/ready" &
SERVER=$!
i=0
while [ ! -e "$W/ready" ]; do
	i=$((i + 1))
	[ "$i" -lt 100 ] || test_skip_all "registry fixture did not start"
	sleep .05
done
ENDPOINT=oci://127.0.0.1:$PORT
export BPM_OCI_SCHEME=http REGISTRY_AUTH_FILE=/absent NO_PROXY='*' no_proxy='*'
unset BPM_OCI_CA_FILE BPM_OCI_PASSWORD BPM_OCI_USERNAME

configure() {
	printf 'endpoint = %s\nindex_repository = %s\nkey_file = /etc/shirudo/bpm/keys/%s\n' \
		"$2" "$3" "${4:-current.der}" >"$SOURCES/$1.conf"
}
refresh_needed() {
	! bpm "$@" 2>"$W/error" && grep -Fq 'shirudo bpm repo update main' "$W/error"
}
installed() {
	printf '{"name":"%s","source":"%s","version":"1.0.0","path":"/var/lib/shirudo/bpm/packages/%s/1.0.0"}' \
		"$1" "$2" "$1"
}
check_other_source() {
	configure other "$ENDPOINT" team/bpm-index &&
	bpm repo update other &&
	printf '{"packages":[%s,%s]}' "$(installed kept main)" \
		"$(installed probe other)" >"$STATE/state.json" &&
	: >"$W/requests" &&
	! bpm upgrade 2>"$W/error" && grep -Fq "$1" "$W/error" &&
	grep -Fq "/v2/team/probe/manifests/$DUMMY" "$W/requests" &&
	printf '{"packages":[%s]}' "$(installed kept main)" >"$STATE/state.json"
}
configure main "$ENDPOINT" team/bpm-index
printf '{"packages":[%s]}' "$(installed kept main)" >"$STATE/state.json"
cp "$W/index.json" "$STATE/repos/main/index.json"

test_expect_success 'install and upgrade require one refresh of a legacy index' '
	refresh_needed install main/probe && refresh_needed upgrade &&
	bpm repo update main && bpm upgrade &&
	! bpm install main/probe &&
	grep -Fq "/v2/team/probe/manifests/$DUMMY" "$W/requests"
'
test_expect_success 'a failed refresh preserves the matching index offline' '
	mv "$REPO/manifests/stable" "$W/stable" &&
	! bpm repo update main && bpm upgrade &&
	mv "$W/stable" "$REPO/manifests/stable"
'
test_expect_success 'the same source name under another endpoint or index needs a refresh' '
	configure main "oci://localhost:$PORT" team/bpm-index &&
	refresh_needed install main/probe && refresh_needed upgrade &&
	configure main "$ENDPOINT" other/bpm-index &&
	refresh_needed install main/probe && refresh_needed upgrade
'
test_expect_success 'upgrade continues with a matching source after one needs a refresh' '
	configure main "$ENDPOINT" other/bpm-index &&
	check_other_source "shirudo bpm repo update main"
'
test_expect_success 'a missing signing certificate leaves other sources usable' '
	configure main "$ENDPOINT" team/bpm-index missing.der &&
	! bpm install main/probe 2>"$W/error" &&
	grep -Fq "cannot read signing certificate for main" "$W/error" &&
	! bpm upgrade 2>"$W/error" &&
	grep -Fq "cannot read signing certificate for main" "$W/error" &&
	check_other_source "cannot read signing certificate for main"
'
test_expect_success 'a rotated certificate at the same image path needs its own verified index' '
	configure main "$ENDPOINT" team/bpm-index &&
	cp "$W/next.der" "$KEYS/current.der" &&
	refresh_needed install main/probe && refresh_needed upgrade &&
	! bpm repo update main && refresh_needed upgrade &&
	publish next && bpm repo update main && bpm upgrade &&
	cp "$W/first.der" "$KEYS/current.der" && refresh_needed upgrade
'
test_expect_success 'a cache write failure keeps the previous source and index together' '
	publish first &&
	mkdir "$STATE/repos/main/index.cache.tmp" &&
	! bpm repo update main && refresh_needed upgrade &&
	rmdir "$STATE/repos/main/index.cache.tmp" &&
	cp "$W/next.der" "$KEYS/current.der" && bpm upgrade
'
test_done
