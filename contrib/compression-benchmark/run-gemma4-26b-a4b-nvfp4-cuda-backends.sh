#!/usr/bin/env bash
# Compare CRIU CUDA backends with Gemma-4-26B-A4B-NVFP4 on a single Blackwell B200/B300.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: sudo ./contrib/compression-benchmark/run-gemma4-26b-a4b-nvfp4-cuda-backends.sh [RESULTS_DIR]

Runs one warmup and one measured checkpoint/restore per CUDA backend
(four cycles total), saving JSON results, console output and the model revision.
RESULTS_DIR must not already exist; by default a directory is created in /var/tmp.

Optional environment:
  MODEL_REVISION  Full model commit hash to use instead of the pinned default:
                 a19cfe00be84568a6867111c9a68c9c44fdcffe6.

Requires the built CRIU and CUDA plugin in this checkout, Podman/runc,
NVIDIA CDI, an r610 or newer driver, and cuda-checkpoint with --launch-job
support in PATH. Backend comparisons create a CUDA checkpoint job by default.
Requires a Blackwell B200/B300 (SM100/SM103) GPU at index 0.
The pinned SGLang H200 Marlin path does not support Gemma's GELU experts.
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

gpu_capability=$(nvidia-smi --id=0 --query-gpu=compute_cap --format=csv,noheader)
case "$gpu_capability" in
    10.0|10.3) ;;
    *)
        echo "Gemma-4-26B-A4B-NVFP4 requires Blackwell B200/B300 (SM100/SM103); GPU 0 is SM $gpu_capability." >&2
        echo "The pinned SGLang H200 Marlin backend does not support this model's GELU experts." >&2
        exit 1
        ;;
esac

if (( $# == 1 )); then
    mkdir -- "$1"
    results_dir=$(cd -- "$1" && pwd)
else
    results_dir=$(mktemp -d /var/tmp/gemma4-26b-a4b-nvfp4-cuda-backends.XXXXXXXX)
fi
# Capture setup failures as well as benchmark output; set -e stops on failure.
exec > >(tee "$results_dir/run.log") 2>&1
printf 'Results directory: %s\n' "$results_dir"

python3 - "$results_dir/model-revision.txt" <<'PY'
import os
import re
import sys

revision = os.environ.get("MODEL_REVISION", "a19cfe00be84568a6867111c9a68c9c44fdcffe6")
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
    --model nvidia/Gemma-4-26B-A4B-NVFP4 \
    --model-revision "$model_revision" \
    --criu-libdir "$repo_dir/plugins/cuda" \
    --cuda-backends driver-api cuda-checkpoint \
    --modes uncompressed \
    --archive-compression none \
    --mem-fraction-static 0.7 \
    --tensor-parallel-size 1 \
    --context-length 8192 \
    --max-total-tokens 8192 \
    --sglang-arg=--disable-radix-cache \
    --sglang-arg=--attention-backend=triton \
    --sglang-arg=--moe-runner-backend=flashinfer_cutlass \
    --warmup-requests 0 \
    --iterations 1 \
    --wait-seconds 3600 \
    --print-stats \
    --json "$results_dir/results.json"

printf 'Completed. Results: %s/results.json\n' "$results_dir"
