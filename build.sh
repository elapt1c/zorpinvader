#!/bin/bash
set -e

echo "=== ZorpInvader Build ==="
echo "Optimizations: opt-level=3, fat LTO, codegen-units=1, panic=abort, stripped"
echo ""

# Native CPU tuning for maximum packet processing speed
export RUSTFLAGS="-C target-cpu=native"

echo "[1/4] Cleaning stale artifacts..."
cargo clean --release 2>/dev/null || true

echo "[2/4] Building release binary..."
cargo build --release 2>&1 | grep -v "^warning:" | grep -v "^   = note:" | grep -v "^   -->" | grep -v "^   |" | grep -v "^$" | grep -v "^   Compiling" | grep -v "^   Downloading" | grep -v "^    Finished" || true

echo "[3/4] Stripping any remaining debug info..."
strip -s target/release/zorpinvader 2>/dev/null || true

echo "[4/4] Deploying binary..."
# Handle "text file busy" if binary is currently running
if [ -f zorpinvader ]; then
    rm -f zorpinvader 2>/dev/null || true
fi
cp target/release/zorpinvader zorpinvader.tmp
mv zorpinvader.tmp zorpinvader
chmod +x zorpinvader

echo ""
echo "=== Build complete ==="
ls -lh zorpinvader
echo ""
file zorpinvader
echo ""
echo "Run with: sudo ./zorpinvader [--rate 5000]"
