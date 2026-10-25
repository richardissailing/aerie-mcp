#!/usr/bin/env bash
# Build build/lambda.zip for the python3.15 arm64 Lambda runtime.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf build/pkg build/lambda.zip
mkdir -p build/pkg

# boto3 is bundled rather than taken from the runtime: AWS recommends it, and the python3.15
# runtime is still in preview, so its bundled SDK version is not something to rely on.
uv export --frozen --no-dev --no-hashes --no-emit-project --format requirements-txt > build/requirements.txt

uv pip install --quiet --target build/pkg --python-version 3.15 \
  --python-platform aarch64-manylinux2014 --only-binary :all: -r build/requirements.txt

cp -r src/falcon_fleet_mcp build/pkg/
cp run.sh build/pkg/
find build/pkg -name '__pycache__' -prune -exec rm -rf {} +

# Lambda's filesystem is read-only, so Python cannot cache bytecode there and would compile every
# module from source on each cold start (about 2.5s instead of 1s). Ship it precompiled. Bytecode is
# platform independent but tied to the minor version; unchecked-hash skips per-import mtime checks.
# A pre-release interpreter writes a different bytecode format, which Lambda would ignore.
uv run --no-project --python 3.15 python -c \
  'import sys; sys.exit(0 if sys.version_info.releaselevel == "final" else f"need a final Python 3.15, got {sys.version}")'
uv run --no-project --python 3.15 python -m compileall -q -j 0 \
  --invalidation-mode unchecked-hash build/pkg > /dev/null

(cd build/pkg && zip -qr9 ../lambda.zip .)
echo "built build/lambda.zip ($(du -h build/lambda.zip | cut -f1))"
