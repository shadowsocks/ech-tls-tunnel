#!/bin/sh
# Install release binaries; configuration and service startup are separate.
set -eu

usage() {
    cat <<'EOF'
Usage: sh install.sh client|server [--bin-dir DIR]

Installs ech-tls-tunnel and sslocal (client) or ssserver (server).
Supports Linux x86_64/ARM64 and macOS ARM64.
Default directory: /usr/local/bin (uses sudo if necessary).

Environment:
  ECH_VERSION  Plugin release tag (default: latest)
  SS_VERSION   shadowsocks-rust release tag (default: v1.25.0)
EOF
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
    client) ss_binary=sslocal ;;
    server) ss_binary=ssserver ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
esac
shift
bin_dir=/usr/local/bin
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail '--bin-dir requires a directory'
            bin_dir=$2
            shift 2
            ;;
        *) fail "Unknown argument: $1" ;;
    esac
done
case "$bin_dir" in /*) ;; *) fail '--bin-dir must be an absolute path' ;; esac

case "$(uname -s):$(uname -m)" in
    Linux:x86_64) suffix=linux-amd64-musl; target=x86_64-unknown-linux-musl ;;
    Linux:aarch64|Linux:arm64) suffix=linux-arm64-musl; target=aarch64-unknown-linux-musl ;;
    Darwin:arm64) suffix=darwin-arm64; target=aarch64-apple-darwin ;;
    *) fail 'Unsupported platform; build from source (see README.md)' ;;
esac

for command in curl tar xz mktemp install; do
    command -v "$command" >/dev/null 2>&1 || fail "Required command missing: $command"
done
if command -v sha256sum >/dev/null 2>&1; then
    checksum=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    checksum=shasum
else
    fail 'Install sha256sum or shasum to verify downloads'
fi

ech_version=${ECH_VERSION:-latest}
ss_version=${SS_VERSION:-v1.25.0}
for version in "$ech_version" "$ss_version"; do
    case "$version" in *[!a-zA-Z0-9._-]*) fail "Invalid release tag: $version" ;; esac
done
[ "$ss_version" != latest ] || fail 'SS_VERSION must be an explicit release tag'

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
trap 'exit 1' HUP INT TERM

download() {
    curl --fail --show-error --silent --location --retry 3 --connect-timeout 15 --max-time 300 \
        --proto '=https' --proto-redir '=https' "$1" -o "$2"
}

fetch_binary() {
    base=$1 archive=$2 binary=$3 destination=$4
    download "$base/$archive" "$tmp_dir/$archive"
    download "$base/$archive.sha256" "$tmp_dir/$archive.sha256"
    # Compare only the digest: never trust a downloaded checksum's file paths.
    expected=$(awk 'NR == 1 { print $1 }' "$tmp_dir/$archive.sha256")
    [ "${#expected}" -eq 64 ] || fail "Invalid checksum for $archive"
    case "$expected" in *[!0-9a-fA-F]*) fail "Invalid checksum for $archive" ;; esac
    if [ "$checksum" = sha256sum ]; then
        actual=$(sha256sum "$tmp_dir/$archive" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$tmp_dir/$archive" | awk '{print $1}')
    fi
    [ "$actual" = "$expected" ] || fail "Checksum mismatch for $archive"
    # Extract only the requested executable, without trusting archive paths.
    tar -xOf "$tmp_dir/$archive" "$binary" > "$destination"
    [ -s "$destination" ] || fail "Empty binary: $binary"
    chmod 755 "$destination"
}

ech_base=https://github.com/shadowsocks/ech-tls-tunnel/releases
if [ "$ech_version" = latest ]; then
    ech_base=$ech_base/latest/download
else
    ech_base=$ech_base/download/$ech_version
fi
ss_base=https://github.com/shadowsocks/shadowsocks-rust/releases/download/$ss_version
printf 'Downloading ech-tls-tunnel and %s for %s...\n' "$ss_binary" "$target"
fetch_binary "$ech_base" "ech-tls-tunnel-$suffix.tar.gz" ech-tls-tunnel "$tmp_dir/ech-tls-tunnel"
fetch_binary "$ss_base" "shadowsocks-$ss_version.$target.tar.xz" "$ss_binary" "$tmp_dir/$ss_binary"

if [ "$(id -u)" -eq 0 ] || { [ -d "$bin_dir" ] && [ -w "$bin_dir" ]; }; then
    install -d "$bin_dir"
    install -m 755 "$tmp_dir/ech-tls-tunnel" "$tmp_dir/$ss_binary" "$bin_dir/"
elif [ ! -e "$bin_dir" ] && [ -w "$(dirname "$bin_dir")" ]; then
    install -d "$bin_dir"
    install -m 755 "$tmp_dir/ech-tls-tunnel" "$tmp_dir/$ss_binary" "$bin_dir/"
else
    command -v sudo >/dev/null 2>&1 || fail 'Use --bin-dir with a writable directory, or install sudo'
    sudo install -d "$bin_dir"
    sudo install -m 755 "$tmp_dir/ech-tls-tunnel" "$tmp_dir/$ss_binary" "$bin_dir/"
fi
printf 'Installed ech-tls-tunnel and %s in %s\n' "$ss_binary" "$bin_dir"
printf 'Ensure this directory is on PATH, then configure your %s:\n' "$ss_binary"
printf 'https://github.com/shadowsocks/ech-tls-tunnel#quick-start\n'
