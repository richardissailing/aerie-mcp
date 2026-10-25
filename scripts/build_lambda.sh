#!/usr/bin/env bash
# Build build/lambda.zip for the python3.13 arm64 Lambda runtime.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf build/pkg build/lambda.zip
mkdir -p build/pkg

# boto3/botocore ship with the Lambda runtime; leaving them out keeps the package small.
uv export --frozen --no-dev --no-hashes --no-emit-project --format requirements-txt \
  | grep -vE '^(boto3|botocore|s3transfer|jmespath)==' > build/requirements.txt

uv pip install --quiet --target build/pkg --python-version 3.13 \
  --python-platform aarch64-manylinux2014 --only-binary :all: -r build/requirements.txt

cp -r src/falcon_fleet_mcp build/pkg/
cp run.sh build/pkg/
find build/pkg -name '__pycache__' -prune -exec rm -rf {} +

(cd build/pkg && zip -qr9 ../lambda.zip .)
echo "built build/lambda.zip ($(du -h build/lambda.zip | cut -f1))"
