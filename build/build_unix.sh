#!/usr/bin/env bash
# Build the same single-file binary on Linux/macOS (useful for CI packaging,
# and proof that the tool itself is portable).
set -euo pipefail
cd "$(dirname "$0")/.."

python3 run_tests.py
python3 -m pip install --upgrade --quiet pyinstaller
python3 -m PyInstaller --clean --noconfirm build/surreal.spec
./dist/surreal --version
./dist/surreal selftest
ls -lh dist/surreal
