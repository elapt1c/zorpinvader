#!/bin/bash
set -e

echo "=== ZorpInvader Build ==="

export RUSTFLAGS="-C target-cpu=native"

echo "[1/3] Building release binary..."
cargo build --release 2>&1 | grep -v "^warning:" | grep -v "^   = note:" | grep -v "^   -->" | grep -v "^   |" | grep -v "^$" | grep -v "^   Compiling" | grep -v "^   Downloading" | grep -v "^    Finished" || true

echo "[2/3] Stripping debug info..."
strip -s target/release/zorpinvader 2>/dev/null || true

echo "[3/3] Deploying..."
rm -f zorpinvader 2>/dev/null || true
cp target/release/zorpinvader ./zorpinvader.tmp
mv ./zorpinvader.tmp ./zorpinvader
chmod +x ./zorpinvader

echo ""
echo "=== Build complete ==="
ls -lh ./zorpinvader
echo ""
echo "Run: sudo ./zorpinvader --rate 10000 --ports 80,8080,8443"
