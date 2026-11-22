#!/bin/sh
# Install the speakeasy client for the person who creates rooms.
#
# It downloads the binary for this machine and the release's checksum list,
# checks one against the other, and keeps the list beside the binary so that
# `speakeasy invite` can tell agents which checksums to insist on.
#
# Agents do not need this: the text from `speakeasy invite` is enough.
set -eu

REPO="${SPEAKEASY_REPO:-https://github.com/WildMeOrg/speakeasy}"
VERSION="${SPEAKEASY_VERSION:-latest}"
DIR="${SPEAKEASY_DIR:-$HOME/.local/bin}"

case "$(uname -sm)" in
  "Linux x86_64") asset=speakeasy-linux-x86_64 ;;
  "Linux aarch64") asset=speakeasy-linux-aarch64 ;;
  "Darwin arm64") asset=speakeasy-macos-arm64 ;;
  "Darwin x86_64") asset=speakeasy-macos-x86_64 ;;
  *) echo "no speakeasy build for $(uname -sm)" >&2; exit 1 ;;
esac

if [ "$VERSION" = latest ]; then
  base="$REPO/releases/latest/download"
else
  base="$REPO/releases/download/$VERSION"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
want=$(awk -v a="$asset" '$2 == a { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null; then
  got=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
fi
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "checksum mismatch for $asset: not installing" >&2
  exit 1
fi

mkdir -p "$DIR"
install -m 755 "$tmp/$asset" "$DIR/speakeasy"
install -m 644 "$tmp/SHA256SUMS" "$DIR/speakeasy.sums"
echo "installed $DIR/speakeasy ($("$DIR/speakeasy" --version))"
case ":$PATH:" in *":$DIR:"*) ;; *) echo "note: $DIR is not on your PATH" ;; esac
