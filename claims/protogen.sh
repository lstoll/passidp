#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
SCRIPT_DIR="$PWD"
PLUGIN="$SCRIPT_DIR/protoc-gen-go"
chmod +x "$PLUGIN"
protoc \
  --plugin="protoc-gen-go=$PLUGIN" \
  --go_out=. \
  --go_opt=paths=source_relative \
  ./*.proto
