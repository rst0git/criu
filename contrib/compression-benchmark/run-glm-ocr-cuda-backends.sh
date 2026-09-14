#!/usr/bin/env bash
# Compare CRIU CUDA backends with GLM-OCR on a single H200.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: sudo ./contrib/compression-benchmark/run-glm-ocr-cuda-backends.sh [RESULTS_DIR]

Runs one excluded warmup and ITERATIONS measured cycles per CUDA backend
(default 1: four cycles total), saving JSON results, console output and the model revision.
RESULTS_DIR must not already exist; by default a directory is created in /var/tmp.
Uses local checkpoint directories without archive export/import.
Serving runs offline: download the pinned model into the HF cache first.

Optional environment:
  ITERATIONS     Positive measured cycles per backend (default: 1, smoke test).
                 Use 4 or more to examine variability and backend differences.
  MODEL_REVISION  Full model commit hash to use instead of the pinned default:
                 2e85a62840ccac27daa451df36c736c4636b8628.

Requires the built CRIU and CUDA plugin in this checkout, Podman/runc,
NVIDIA CDI, an r610 or newer driver, and cuda-checkpoint with --launch-job
support in PATH. Backend comparisons create a CUDA checkpoint job by default.
Uses native BF16 weights and FA3 attention on H200. Recognizes a fixed seal
image from the official GLM-OCR repository, with a 128-token output limit.
Downloads and verifies the image once before starting the benchmark, and saves
seal.jpg, image-info.json and request.json alongside the results.
Temporarily edits /etc/criu/runc.conf using the benchmark's configuration lock
and restoration mechanism.
HELP
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    usage
    exit 0
fi
if (( $# > 1 )); then
    usage >&2
    exit 2
fi
iterations=${ITERATIONS-1}
if [[ ! $iterations =~ ^[1-9][0-9]*$ ]]; then
    echo 'ITERATIONS must be a positive integer.' >&2
    exit 2
fi
if (( EUID != 0 )); then
    echo 'Run this script with sudo on the benchmark host.' >&2
    exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
export PATH="$repo_dir/criu:$PATH"

for command in python3 podman runc nvidia-smi cuda-checkpoint; do
    if ! command -v "$command" >/dev/null; then
        echo "Required command not found: $command" >&2
        exit 1
    fi
done
if [[ ! -x $repo_dir/criu/criu || ! -f $repo_dir/plugins/cuda/cuda_plugin.so ]]; then
    echo "Build CRIU and plugins/cuda in $repo_dir before running." >&2
    exit 1
fi

if (( $# == 1 )); then
    mkdir -- "$1"
    results_dir=$(cd -- "$1" && pwd)
else
    results_dir=$(mktemp -d /var/tmp/glm-ocr-cuda-backends.XXXXXXXX)
fi
# Capture setup failures as well as benchmark output; set -e stops on failure.
exec > >(tee "$results_dir/run.log") 2>&1
printf 'Results directory: %s\n' "$results_dir"

python3 - "$results_dir" <<'PY'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

results_dir = Path(sys.argv[1])
revision = os.environ.get("MODEL_REVISION", "2e85a62840ccac27daa451df36c736c4636b8628")
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit("MODEL_REVISION must be a full lowercase model commit hash")
with (results_dir / "model-revision.txt").open("x") as output:
    output.write(revision + "\n")
print("Model revision:", revision, flush=True)

image_url = (
    "https://raw.githubusercontent.com/zai-org/GLM-OCR/"
    "cef4d0ea120d1741f5cefe8985eee45f6c8eff1d/examples/source/seal.png"
)
image_sha256 = "2aa586757a8fd722bb1b81b14657d667ff2707cd37c91230aaa5477f9285e504"
print("Downloading the pinned OCR image", flush=True)
with urllib.request.urlopen(image_url, timeout=60) as response:
    # The pinned image is 21025 bytes; reject oversized responses without buffering them.
    image_data = response.read(21026)
if hashlib.sha256(image_data).hexdigest() != image_sha256:
    raise SystemExit("OCR image SHA256 does not match the pinned fixture")
# The upstream .png file contains JPEG data.
with (results_dir / "seal.jpg").open("xb") as output:
    output.write(image_data)
with (results_dir / "image-info.json").open("x") as output:
    json.dump({
        "source_url": image_url,
        "sha256": image_sha256,
        "model_revision": revision,
    }, output, indent=2)
    output.write("\n")

request = {
    "messages": [{
        "role": "user",
        "content": [
            {"type": "image_url", "image_url": {
                "url": "data:image/jpeg;base64," + base64.b64encode(image_data).decode("ascii"),
            }},
            {"type": "text", "text": "Text Recognition:"},
        ],
    }],
    # Keep the supported OCR prompt without appending /nothink.
    "chat_template_kwargs": {},
}
with (results_dir / "request.json").open("x") as output:
    json.dump(request, output, indent=2)
    output.write("\n")
PY
model_revision=$(cat "$results_dir/model-revision.txt")
image='docker.io/lmsysorg/sglang:v0.5.17-cu130-runtime'
digest='3ea7c6d74312d964edbcf9b3819425ea42117eb967ef1cfec632a70c926027df'

python3 "$script_dir/podman-sglang.py" \
    --image "${image}@sha256:${digest}" \
    --model zai-org/GLM-OCR \
    --model-revision "$model_revision" \
    --criu-libdir "$repo_dir/plugins/cuda" \
    --cuda-backends driver-api cuda-checkpoint \
    --modes uncompressed \
    --checkpoint-storage local \
    --archive-compression none \
    --mem-fraction-static 0.35 \
    --tensor-parallel-size 1 \
    --context-length 8192 \
    --max-total-tokens 8192 \
    --sglang-arg=--disable-radix-cache \
    --sglang-arg=--attention-backend=fa3 \
    --prompt 'Text Recognition:' \
    --max-tokens 128 \
    --chat-extra-json "$(cat "$results_dir/request.json")" \
    --offline \
    --warmup-requests 0 \
    --iterations "$iterations" \
    --wait-seconds 3600 \
    --print-stats \
    --json "$results_dir/results.json"

printf 'Completed. Results: %s/results.json\n' "$results_dir"
