#!/usr/bin/env bash
# Compare CRIU CUDA backends with NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16 on a single H200.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: sudo ./contrib/compression-benchmark/run-nemotron35-lightning-30b-a3b-bf16-cuda-backends.sh [RESULTS_DIR]

Runs one excluded warmup and ITERATIONS measured cycles per CUDA backend
(default 1: four cycles total), saving JSON results, console output and the model revision.
RESULTS_DIR must not already exist; by default a directory is created in /var/tmp.
Uses local checkpoint directories without archive export/import.
Serving runs offline: download the pinned model into the HF cache first.

Optional environment:
  ITERATIONS     Positive measured cycles per backend (default: 1, smoke test).
                 Use 4 or more to examine variability and backend differences.
  MODEL_REVISION  Full model commit hash to use instead of the pinned default:
                 a9904d24bcc1d289a1950fa9d2b978c47cf903b9.

Requires the built CRIU and CUDA plugin in this checkout, Podman/runc,
NVIDIA CDI, an r610 or newer driver, and cuda-checkpoint with --launch-job
support in PATH. Backend comparisons create a CUDA checkpoint job by default.
Uses native BF16 weights, FA3 attention and CUTLASS experts on H200.
Thinking is disabled and the output limit is 32 tokens.
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
    results_dir=$(mktemp -d /var/tmp/nemotron35-lightning-30b-a3b-bf16-cuda-backends.XXXXXXXX)
fi
# Capture setup failures as well as benchmark output; set -e stops on failure.
exec > >(tee "$results_dir/run.log") 2>&1
printf 'Results directory: %s\n' "$results_dir"

python3 - "$results_dir/model-revision.txt" <<'PY'
import os
import re
import sys

revision = os.environ.get("MODEL_REVISION", "a9904d24bcc1d289a1950fa9d2b978c47cf903b9")
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit("MODEL_REVISION must be a full lowercase model commit hash")
with open(sys.argv[1], "x") as output:
    output.write(revision + "\n")
print("Model revision:", revision)
PY
model_revision=$(cat "$results_dir/model-revision.txt")
image='docker.io/lmsysorg/sglang:v0.5.17-cu130-runtime'
digest='3ea7c6d74312d964edbcf9b3819425ea42117eb967ef1cfec632a70c926027df'

python3 "$script_dir/podman-sglang.py" \
    --image "${image}@sha256:${digest}" \
    --model nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16 \
    --model-revision "$model_revision" \
    --criu-libdir "$repo_dir/plugins/cuda" \
    --cuda-backends driver-api cuda-checkpoint \
    --modes uncompressed \
    --checkpoint-storage local \
    --archive-compression none \
    --mem-fraction-static 0.7 \
    --tensor-parallel-size 1 \
    --context-length 8192 \
    --max-total-tokens 8192 \
    --sglang-arg=--disable-radix-cache \
    --sglang-arg=--dtype=bfloat16 \
    --sglang-arg=--attention-backend=fa3 \
    --sglang-arg=--moe-runner-backend=flashinfer_cutlass \
    --offline \
    --warmup-requests 0 \
    --iterations "$iterations" \
    --wait-seconds 3600 \
    --print-stats \
    --json "$results_dir/results.json"

printf 'Completed. Results: %s/results.json\n' "$results_dir"
