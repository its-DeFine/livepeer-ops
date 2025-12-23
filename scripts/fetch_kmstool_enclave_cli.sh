#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${DEST_DIR:-$ROOT_DIR/enclave}"
SDK_DIR="${SDK_DIR:-/tmp/aws-nitro-enclaves-sdk-c}"
SDK_REF="${SDK_REF:-v0.4.3}"

if [[ "$DEST_DIR" != /* ]]; then
  DEST_DIR="$ROOT_DIR/$DEST_DIR"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required (run this on an enclave-capable EC2 instance)" >&2
  exit 1
fi

mkdir -p "$DEST_DIR"

if [ ! -d "$SDK_DIR/.git" ]; then
  rm -rf "$SDK_DIR"
  git clone --depth 1 --branch "$SDK_REF" https://github.com/aws/aws-nitro-enclaves-sdk-c.git "$SDK_DIR"
fi

pushd "$SDK_DIR/bin/kmstool-enclave-cli" >/dev/null
./build.sh
cp -f ./kmstool_enclave_cli "$DEST_DIR/kmstool_enclave_cli"
cp -f ./libnsm.so "$DEST_DIR/libnsm.so"
chmod +x "$DEST_DIR/kmstool_enclave_cli"
popd >/dev/null

echo "Wrote:"
echo "  $DEST_DIR/kmstool_enclave_cli"
echo "  $DEST_DIR/libnsm.so"
