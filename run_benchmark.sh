#!/bin/bash

set -e  # stop on error

echo "Starting full dataset run..."
echo "======================================"

mkdir -p reports

for f in datasets/positive/*.sol datasets/negative/*.sol datasets/edge/*.sol; do
    echo "--------------------------------------"
    echo "Running: $f"
    python -m pipeline.runner "$f"
done

echo "======================================"
echo "Done. Reports saved in /reports"