#!/usr/bin/env bash
# generate_stubs.sh
#
# Clones cilium/tetragon at a given tag and compiles its .proto files into the
# Python gRPC stubs this project imports (`from tetragon.events_pb2 import ...`).
#
# Usage:
#   ./generate_stubs.sh [output_dir]            # default output_dir: ..
#   TETRAGON_REF=v1.6.0 ./generate_stubs.sh     # match your installed daemon
#
# Match TETRAGON_REF to your daemon's version (`tetragon --help` / `tetra version`)
# to avoid client/server schema drift. Default: v1.7.1.

set -euo pipefail

REF="${TETRAGON_REF:-v1.7.1}"
OUT_DIR="${1:-..}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "[*] Cloning cilium/tetragon @ $REF (shallow)..."
git clone --quiet --depth 1 --branch "$REF" https://github.com/cilium/tetragon.git "$WORK_DIR/tetragon"

echo "[*] Installing grpcio-tools if needed..."
python3 -m pip install -q grpcio grpcio-tools || python3 -m pip install -q --break-system-packages grpcio grpcio-tools

echo "[*] Generating Python stubs into: $OUT_DIR"
mkdir -p "$OUT_DIR"
python3 -m grpc_tools.protoc \
  -I "$WORK_DIR/tetragon/api/v1" \
  --python_out="$OUT_DIR" \
  --grpc_python_out="$OUT_DIR" \
  "$WORK_DIR/tetragon/api/v1/tetragon/"*.proto

echo "[+] Done ($REF). Importable as: from tetragon.events_pb2 import ..."
