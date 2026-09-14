#!/usr/bin/env bash
# Compare CRIU CUDA backends with NVIDIA's realtime VoiceChat container.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: sudo ./contrib/compression-benchmark/run-voicechat-11b-cuda-backends.sh MODEL_REPO INPUT_WAV [RESULTS_DIR]

MODEL_REPO is a converted Triton repository containing nemotron-voicechat/.
INPUT_WAV must be a fixed 24 kHz mono PCM16 speech recording. The client adds
20 seconds of silence so the full-duplex model has time to respond.
See CUDA-BACKENDS.md for pinned model preparation instructions.

Runs one warmup and one measured checkpoint/restore per CUDA backend
(four cycles total), saving results.json, run.log and speech artifacts.
RESULTS_DIR must not already exist; by default a directory is created in /var/tmp.

Requires the built CRIU and CUDA plugin, Podman/runc, NVIDIA CDI, an r610 or
newer driver, cuda-checkpoint with --launch-job, and Python websockets>=14.
Uses live GPU state; there are no SGLang memory-saver calls. Ports 8000, 8001,
8002 and 9000 must be unused. The model requires an 80 GB or larger GPU.
Validation requires speech output and matching input transcripts, without
requiring identical generated speech from the API's unseeded sampler.
Temporarily edits /etc/criu/runc.conf using the shared configuration lock
and restoration mechanism.
HELP
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    usage
    exit 0
fi
if (( $# < 2 || $# > 3 )); then
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

if (( $# == 3 )); then
    mkdir -- "$3"
    results_dir=$(cd -- "$3" && pwd)
else
    results_dir=$(mktemp -d /var/tmp/voicechat-11b-cuda-backends.XXXXXXXX)
fi
exec > >(tee "$results_dir/run.log") 2>&1
printf 'Results directory: %s\n' "$results_dir"
image='nvcr.io/nim/nvidia/nemotron-labs-voicechat'
digest='6e69ff2aac955be2cb65b0de4f5b6d7c0b5e45ca0a1d42a2b153e9b54efb059b'
model_revision='a4c40ca5b4fe77db13e9840ca4a2b91becf030c8'
printf '%s\n' "$model_revision" > "$results_dir/model-revision.txt"

python3 "$script_dir/podman-voicechat.py" \
    --image "${image}@sha256:${digest}" \
    --model-revision "$model_revision" \
    --model-repo "$1" \
    --audio "$2" \
    --artifacts-dir "$results_dir/speech" \
    --criu-libdir "$repo_dir/plugins/cuda" \
    --cuda-backends driver-api cuda-checkpoint \
    --modes uncompressed \
    --archive-compression none \
    --warmup-requests 0 \
    --iterations 1 \
    --wait-seconds 3600 \
    --request-timeout 180 \
    --print-stats \
    --json "$results_dir/results.json"

printf 'Completed. Results: %s/results.json\n' "$results_dir"
