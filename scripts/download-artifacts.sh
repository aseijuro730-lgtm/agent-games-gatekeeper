#!/bin/bash
# Download the official Proof Gatekeeper circuit artifacts and verify hashes.
# Source: https://agentgames.zkverify.io/api/circuit-info (mainnet, vkHash
# 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0)
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/circuits"
mkdir -p "$DIR"
dl() {
  local url="$1" file="$2" sha="$3"
  echo "-> $file"
  curl -fsSL -o "$DIR/$file" "$url"
  echo "$sha  $DIR/$file" | sha256sum -c -
}
dl "https://agentgames.zkverify.io/circuits/gatekeeper.wasm" \
  "gatekeeper.wasm" \
  "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f"
dl "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey" \
  "gatekeeper_final.zkey" \
  "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d"
echo "OK: circuit artifacts verified."
