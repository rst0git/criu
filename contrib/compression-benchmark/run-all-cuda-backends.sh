#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'HELP'
Usage: run-all-cuda-backends.sh [--iterations N] [--results-root DIR]
       [--skip-voicechat] [--voicechat-model-repo DIR --voicechat-audio FILE]
       [--no-download-models] [--commit]

Run all checked-in CUDA backend benchmarks sequentially. Model revisions are
downloaded into the benchmark cache before the offline trials. Results are
stored in the checkout. --commit records only complete results and never
pushes remotely.
HELP
}

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
iterations=1; results_root=; skip_voicechat=false; commit_results=false
download_models=true
voicechat_model_repo=; voicechat_audio=
while (($#)); do
    case "$1" in
        --iterations) (($# >= 2)) || exit 2; iterations=$2; shift 2 ;;
        --results-root) (($# >= 2)) || exit 2; results_root=$2; shift 2 ;;
        --voicechat-model-repo) (($# >= 2)) || exit 2; voicechat_model_repo=$2; shift 2 ;;
        --voicechat-audio) (($# >= 2)) || exit 2; voicechat_audio=$2; shift 2 ;;
        --skip-voicechat) skip_voicechat=true; shift ;;
        --no-download-models) download_models=false; shift ;;
        --commit) commit_results=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ $iterations =~ ^[1-9][0-9]*$ ]] || { echo "iterations must be positive" >&2; exit 2; }
((EUID == 0)) || { echo "Run as root (sudo $0 ...)" >&2; exit 1; }
if [[ $skip_voicechat == false ]]; then
    [[ -d $voicechat_model_repo && -f $voicechat_audio ]] || {
        echo "VoiceChat requires --voicechat-model-repo and --voicechat-audio" >&2
        echo "Use --skip-voicechat to omit it." >&2; exit 2;
    }
fi
if [[ -z $results_root ]]; then results_root="benchmark-results/all-cuda-backends-$(date -u +%Y%m%dT%H%M%SZ)"; fi
if [[ $results_root != /* ]]; then results_root="$repo_dir/$results_root"; fi
results_root=$(readlink -m -- "$results_root")
[[ ! -e $results_root ]] || { echo "Results directory exists: $results_root" >&2; exit 2; }

models=(
    'google/gemma-4-26B-A4B-it|4d7ae4984b7db7de8f8457170b3f1a419ee76d52|'
    'google/gemma-4-31B-it|842da3794eaa0b77d5f08bae87a17459d91ff475|'
    'zai-org/GLM-OCR|2e85a62840ccac27daa451df36c736c4636b8628|'
    'zai-org/GLM-4.7-Flash|7dd20894a642a0aa287e9827cb1a1f7f91386b67|'
    'openai/gpt-oss-120b|b5c939de8f754692c1647ca79fbf85e8c1e70f8a|original/*'
    'nvidia/NVIDIA-Nemotron-3-Nano-4B-BF16|dfaf35de3e30f1867dd8dbc38a7fc9fb52d3914f|'
    'nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-FP8|744b1880a37996c5d56bf454ae164dfd74d77c4e|'
    'nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16|a9904d24bcc1d289a1950fa9d2b978c47cf903b9|'
    'Qwen/Qwen3.6-35B-A3B-FP8|95a723d08a9490559dae23d0cff1d9466213d989|'
    'Qwen/Qwen3.6-27B||'
    'Qwen/Qwen3.8-27B-FP8|017b9c7af6b5689d5dd426a76e0bc077eb5ca20a|'
)

if [[ $download_models == true ]]; then
    command -v hf >/dev/null || { echo "hf CLI is required for model preparation" >&2; exit 1; }
    hf_cache=${HF_HOME:-/root/.cache/huggingface}/hub
    for specification in "${models[@]}"; do
        IFS='|' read -r model revision exclude <<<"$specification"
        download=(hf download "$model" --cache-dir "$hf_cache")
        [[ -n $revision ]] && download+=(--revision "$revision")
        [[ -n $exclude ]] && download+=(--exclude "$exclude")
        echo "Preparing $model${revision:+@$revision}"
        "${download[@]}"
    done
fi

mkdir -p -- "$results_root"
exec > >(tee "$results_root/run.log") 2>&1

runners=(
    run-gemma4-26b-a4b-bf16-cuda-backends.sh run-gemma4-31b-it-bf16-cuda-backends.sh
    run-glm-ocr-cuda-backends.sh run-glm47-flash-cuda-backends.sh
    run-gpt-oss-120b-cuda-backends.sh run-nemotron3-nano-4b-bf16-cuda-backends.sh
    run-nemotron3-super-120b-a12b-fp8-cuda-backends.sh
    run-nemotron35-lightning-30b-a3b-bf16-cuda-backends.sh
    run-qwen36-35b-a3b-fp8-cuda-backends.sh run-qwen36-cuda-backends.sh
    run-qwen38-fp8-cuda-backends.sh
)
failed=()
for runner in "${runners[@]}"; do
    name=${runner%.sh}; echo "===== $runner ====="
    if ! ITERATIONS="$iterations" "contrib/compression-benchmark/$runner" "$results_root/$name"; then
        failed+=("$runner"); echo "FAILED: $runner" >&2
    fi
done
if [[ $skip_voicechat == false ]]; then
    runner=run-voicechat-11b-cuda-backends.sh; echo "===== $runner ====="
    if ! ITERATIONS="$iterations" "contrib/compression-benchmark/$runner" "$voicechat_model_repo" "$voicechat_audio" "$results_root/voicechat"; then
        failed+=("$runner"); echo "FAILED: $runner" >&2
    fi
fi
if ((${#failed[@]})); then
    printf 'Failed runners:\n  %s\n' "${failed[@]}" >&2
    exit 1
fi
python3 -c 'import json, pathlib, sys; files=sorted(pathlib.Path(sys.argv[1]).glob("*/results.json")); assert files, "No results.json files found"; bad=[]; [print(f"{p}: {json.loads(p.read_text()).get(\"status\")}") or (bad.append(str(p)) if json.loads(p.read_text()).get("status") != "complete" else None) for p in files]; raise SystemExit("Incomplete results:\n" + "\n".join(bad)) if bad else None' "$results_root"
relative_root=${results_root#"$repo_dir/"}
if [[ $commit_results == true ]]; then
    [[ $relative_root != "$results_root" ]] || { echo "--commit requires results inside the checkout" >&2; exit 2; }
    git add -- "$relative_root"
    git commit -s -m "benchmarks: record CUDA backend results"
else
    echo "Complete results ready in $relative_root"
    echo "Review, then: git add -- $relative_root && git commit -s -m 'benchmarks: record CUDA backend results'"
fi
