# SGLang CUDA backend comparison

Use the existing `podman-sglang.py` benchmark on an otherwise idle GPU host.
The experiment measures the effect of choosing CRIU's `driver-api` versus
`cuda-checkpoint` backend for the same real SGLang workload. It does not measure
isolated CUDA API call latency: checkpoint/restore wall times include Podman,
runc, CRIU, image storage and archive handling. `restore_to_first_token_us`
also includes memory resumption, readiness polling and the first inference.

Both backends use the same binary, plugin, image digest, model commit, request,
memory saver and compression settings. Each configuration has one excluded
warmup trial followed by N measured trials. Order rotates each round (AB, BA).
The model cache is warm after initial loading; this is not a cold-download test.
Memory saver releases managed GPU allocations before checkpoint, matching the
snapshot lifecycle. CPU weight backup preserves model parameters in host memory,
which CRIU includes in its images and SGLang copies back to the GPU on resume.
Without that backup, release/resume discards the model weights. These results
include weight storage and transfer, but do not describe copying the full live
VRAM footprint. Use the same storage and GPU assignment for all trials.

## Minimal Qwen3.6-27B run

For the single-H200 evaluation, run the checked-in script from the checkout:

```bash
sudo ./contrib/compression-benchmark/run-qwen36-cuda-backends.sh
```

It uses CRIU and the CUDA plugin from its own checkout, the pinned SGLang image,
Qwen3.6-27B, a 70% GPU memory budget and an 8192-token context. It runs one
excluded warmup and one measured cycle per backend (four cycles total), with
no extra warmup inference requests. This provides an initial comparison, not
an estimate of run-to-run variability. Validation remains enabled.

The script prints its new results directory under `/var/tmp`, containing
`results.json`, `run.log` and `model-revision.txt`. An optional positional
argument selects a new results directory. To repeat with the same model commit:

```bash
sudo env MODEL_REVISION="$(cat /path/to/previous/model-revision.txt)" \
  ./contrib/compression-benchmark/run-qwen36-cuda-backends.sh
```

Otherwise the script resolves the current model commit once before starting
and saves it. Use `--help` for prerequisites. The script is intended to be run
by the user on the benchmark host; it does not connect over SSH itself.

### Qwen3.8-27B-FP8

Use the separate runner for
[Qwen3.8-27B-FP8](https://huggingface.co/Qwen/Qwen3.8-27B-FP8) on the benchmark
host after the previous benchmark finishes. It pins the model to revision
`017b9c7af6b5689d5dd426a76e0bc077eb5ca20a`:

```bash
cd /var/tmp/criu
# Optional: populate the root user's cache before timing the benchmark.
sudo hf download Qwen/Qwen3.8-27B-FP8 \
  --revision 017b9c7af6b5689d5dd426a76e0bc077eb5ca20a \
  --cache-dir /root/.cache/huggingface/hub

sudo ./contrib/compression-benchmark/run-qwen38-fp8-cuda-backends.sh
```

This keeps the same image, memory settings, validation and four-cycle schedule.
SGLang reads FP8 quantization from the model configuration. CPU weight backup
remains enabled to preserve weights across memory release and resumption.
The new run saves its own results under `/var/tmp/qwen38-fp8-cuda-backends.*`.
An optional positional argument selects a new results directory;
`MODEL_REVISION` overrides the default model pin.
The model uses the Qwen3.5 architecture supported by the pinned SGLang version;
this FP8 checkpoint still needs an end-to-end validation run on the target host.

### GPT-OSS-120B

Use the separate runner for
[openai/gpt-oss-120b](https://huggingface.co/openai/gpt-oss-120b) on the single
H200 host after the previous benchmark finishes:

```bash
cd /var/tmp/criu
sudo ./contrib/compression-benchmark/run-gpt-oss-120b-cuda-backends.sh
```

It pins model revision `b5c939de8f754692c1647ca79fbf85e8c1e70f8a` and reuses the
same SGLang image digest, 70% GPU memory budget, 8192-token context and four-cycle
schedule. SGLang reads the model's MXFP4 quantization configuration. The runner
selects Marlin MoE kernels to keep the expert weights packed on H200 and uses
FA3 attention. Memory saver, CPU weight backup and restore validation remain
enabled.

GPT-OSS uses Harmony reasoning output. The runner enables its reasoning parser,
requests low reasoning effort and allows 128 output tokens. The benchmark
compares the combined reasoning and answer text before and after restore.
These request settings differ from the Qwen runners and are recorded in the
JSON results; compare CUDA backends within each model's run.

Results are saved under `/var/tmp/gpt-oss-120b-cuda-backends.*`, including
`results.json`, `run.log` and `model-revision.txt`. An optional positional
argument selects a new results directory, and `MODEL_REVISION` overrides the
default model pin. To download the Hugging Face weights before the run:

```bash
sudo hf download openai/gpt-oss-120b \
  --revision b5c939de8f754692c1647ca79fbf85e8c1e70f8a \
  --exclude 'original/*' --cache-dir /root/.cache/huggingface/hub
```

The `original/` files are for the model's reference implementation and are not
needed by SGLang. GPU startup and checkpoint/restore still require validation
on the target host.

### GLM-4.7-Flash

Use the separate runner for
[zai-org/GLM-4.7-Flash](https://huggingface.co/zai-org/GLM-4.7-Flash) on the single
H200 host after the previous benchmark finishes:

```bash
cd /var/tmp/criu
sudo ./contrib/compression-benchmark/run-glm47-flash-cuda-backends.sh
```

It pins model revision `7dd20894a642a0aa287e9827cb1a1f7f91386b67` and uses the
native BF16 weights with the same SGLang image digest, 70% GPU memory budget,
8192-token context and four-cycle schedule. The benchmark disables thinking
through the model's chat template and uses the `glm45` reasoning parser with
a 32-token output limit. Memory saver, CPU weight backup and restore validation
remain enabled.

Results are saved under `/var/tmp/glm47-flash-cuda-backends.*`, including
`results.json`, `run.log` and `model-revision.txt`. An optional positional
argument selects a new results directory, and `MODEL_REVISION` overrides the
default model pin. To download the weights before the run:

```bash
sudo hf download zai-org/GLM-4.7-Flash \
  --revision 7dd20894a642a0aa287e9827cb1a1f7f91386b67 \
  --cache-dir /root/.cache/huggingface/hub
```

GPU startup and checkpoint/restore still require validation on the target host.

### Additional H200 models

These separate runners use the same pinned SGLang image, 8192-token context
and four-cycle schedule: one excluded warmup and one measured checkpoint/restore
per backend. Thinking is disabled with a 32-token output limit. Memory saver,
CPU weight backup and restore validation remain enabled. The GPU memory budget
is 70%, except for the memory-constrained Super-120B configuration below.

| Model | Precision | Runner in `contrib/compression-benchmark/` |
| --- | --- | --- |
| [Qwen3.6-35B-A3B-FP8](https://huggingface.co/Qwen/Qwen3.6-35B-A3B-FP8) | FP8 | `run-qwen36-35b-a3b-fp8-cuda-backends.sh` |
| [gemma-4-31B-it](https://huggingface.co/google/gemma-4-31B-it) | BF16 | `run-gemma4-31b-it-bf16-cuda-backends.sh` |
| [gemma-4-26B-A4B-it](https://huggingface.co/google/gemma-4-26B-A4B-it) | BF16 | `run-gemma4-26b-a4b-bf16-cuda-backends.sh` |
| [NVIDIA-Nemotron-3-Nano-4B-BF16](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-BF16) | BF16 | `run-nemotron3-nano-4b-bf16-cuda-backends.sh` |
| [NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16](https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16) | BF16 | `run-nemotron35-lightning-30b-a3b-bf16-cuda-backends.sh` |
| [NVIDIA-Nemotron-3-Super-120B-A12B-FP8](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-FP8) | FP8 | `run-nemotron3-super-120b-a12b-fp8-cuda-backends.sh` |

Each runner pins a full model revision; `--help` displays the pin. An optional
`MODEL_REVISION` environment variable overrides it with another full commit hash.
For example, run Gemma-26B from the updated checkout on the benchmark host:

```bash
cd /var/tmp/criu
sudo ./contrib/compression-benchmark/run-gemma4-26b-a4b-bf16-cuda-backends.sh
```

Results go into a model-specific directory under `/var/tmp`, containing
`results.json`, `run.log` and `model-revision.txt`. A positional argument selects
a new results directory. To download weights before starting, use `hf download`
with the runner's model and pinned `--revision`, and
`--cache-dir /root/.cache/huggingface/hub` to populate the default benchmark cache.

Qwen uses native block FP8 kernels on H200. Gemma uses the original BF16 weights
and Triton attention; the 26B model also selects Triton MoE, which supports its
GELU experts on H200. Lightning uses BF16 weights and CUTLASS MoE. All three
Nemotron runners use FA3 attention. Gemma-26B, Gemma-31B and Lightning have weight
footprints of approximately 48, 58 and 61 GiB, respectively, before runtime
allocations. Their CPU backups and checkpoint archives will be larger than the
former quantized runs; compare backend results from the same model and precision.

**Super-120B FP8 requires a separate single-H200 smoke test.** Its weight files
occupy about 120 GiB, which exceeds the former 70% GPU memory budget. Its runner
uses 95%, caps concurrent requests and CUDA graph batch size at 1, and selects
native ModelOpt FP8 with CUTLASS MoE. This leaves limited runtime headroom on
H200. NVIDIA's [model card](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-FP8)
lists two H100-80GB GPUs as the minimum and explicitly documents single-GPU
B200/B300 deployment; single-H200 loading and restore are unverified. CPU weight
backup also needs substantial host RAM. A failed load or restore does not
produce a completed comparison.

All launch settings have been checked against the pinned source. GPU startup
and checkpoint/restore still require validation on the target host.

## Run

Prerequisites: built CRIU and CUDA plugin, Podman/runc checkpoint support,
NVIDIA CDI configuration, an r610 or newer driver, a compatible SGLang image,
and `cuda-checkpoint` with `--launch-job` support installed in PATH. Backend
comparisons launch SGLang in a CUDA checkpoint job by default, so its workers
inherit the job identity needed for CUDA IPC checkpointing. Releasing GPU
memory through memory saver does not replace that identity.

Avoid other checkpoint jobs: the benchmark locks and temporarily edits
`/etc/criu/runc.conf`, then restores it on exit.
It explicitly sets `libdir` and the backend in that file; no manual backend
switching is needed. The CLI backend is named `cuda-checkpoint`, not `cli`.
The server port must be unused before each trial; a leftover server would
otherwise receive the benchmark's health, inference, and memory-control calls.

Run from the checkout on the benchmark host. Resolve the model revision once
and retain it alongside the results; reuse that revision for later comparisons.

```bash
cd /var/tmp/criu
set -o pipefail
mkdir -p cuda-backend-results
python3 - <<'PY' > cuda-backend-results/model-revision.txt
import json
import urllib.request
with urllib.request.urlopen('https://huggingface.co/api/models/Qwen/Qwen3-0.6B') as response:
    print(json.load(response)['sha'])
PY
MODEL_REVISION=$(cat cuda-backend-results/model-revision.txt)
IMAGE='docker.io/lmsysorg/sglang:v0.5.17-cu130-runtime'
DIGEST='3ea7c6d74312d964edbcf9b3819425ea42117eb967ef1cfec632a70c926027df'
sudo env PATH="/var/tmp/criu/criu:$PATH" \
  python3 contrib/compression-benchmark/podman-sglang.py \
  --image "${IMAGE}@sha256:${DIGEST}" \
  --model Qwen/Qwen3-0.6B --model-revision "$MODEL_REVISION" \
  --criu-libdir /var/tmp/criu/plugins/cuda \
  --cuda-backends driver-api cuda-checkpoint \
  --modes uncompressed --archive-compression none \
  --sglang-arg=--disable-radix-cache \
  --warmup-requests 2 --iterations 10 --print-stats \
  --json cuda-backend-results/results.json \
  2>&1 | tee cuda-backend-results/run.log
```

For a smoke test, first use `--iterations 1` and a different JSON/log filename.
Existing comparison JSON files are not overwritten. The pin above is the image
used during investigation; compatibility on another host must be checked there.
Disabling radix caching keeps both validation requests on an uncached prompt
path: memory release clears the cache that otherwise benefits only the request
before checkpoint. This is an experimental control, not a guarantee of exact
numerical reproducibility. A mismatch still fails the benchmark.

## Results and interpretation

`results.json` is updated atomically after every completed or failed trial.
It contains system information, executable SHA-256 hashes for CRIU, the plugin
and the required CUDA utilities, GPU UUID and driver version, runc version,
and the run arguments. `results` groups measured samples by configuration;
`warmups` contains the excluded warmup samples, and `failures` records failed
trials. Successful samples include their `trial` number and `configuration`,
so trial order can be reconstructed across the groups. Checkpoint wall time,
restore wall time and restore-to-first-token time are in microseconds.
The console report compares medians; retain the raw samples and report their
spread as well.

Only use a file with `status: complete` as a completed comparison. Errors are
recorded with the failed configuration and artifact directory; no failed trial
is added to successful timing samples. On output mismatch, `validation.json`
in that directory contains both generated texts. Investigate mismatches before
making performance claims. Other failures may still lose container-owned CRIU
logs during the existing container cleanup; the console log retains Podman's
error excerpt. Checkpoint archives are temporary and can be large.

The difference between backend wall-time distributions estimates their impact
on this workload. It is not absolute plugin overhead versus no plugin (a real
CUDA workload needs checkpoint support), and overlapping distributions may not
resolve a small difference. CUDA-operation-only attribution requires separate
instrumentation and an assessment of that instrumentation's overhead.

Local verification (no GPU or container launch):

```bash
python3 test/others/compression/benchmark/test_config.py
```
