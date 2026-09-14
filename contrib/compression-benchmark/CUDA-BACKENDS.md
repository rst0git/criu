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
snapshot lifecycle; these results do not describe copying the full live VRAM
footprint. Use the same storage and GPU assignment for all trials.

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
