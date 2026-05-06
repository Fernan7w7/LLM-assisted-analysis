#!/bin/bash

set -e  # stop on error

echo "Starting full dataset run..."
echo "======================================"

mkdir -p reports

while IFS= read -r -d '' f; do
    echo "--------------------------------------"
    echo "Running: $f"
    python -m pipeline.runner "$f"
done < <(find datasets/synthetic datasets/real -name "*.sol" -print0 | sort -z)

echo "======================================"
echo "Done. Reports saved in reports/"
