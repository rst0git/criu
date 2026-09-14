# CUDA backend comparison

Use the existing `podman-sglang.py` benchmark on an otherwise idle GPU host.
The experiment measures the effect of choosing CRIU's `driver-api` versus
`cuda-checkpoint` backend for the same real SGLang workload. It does not measure
isolated CUDA API call latency: checkpoint/restore wall times include Podman,
runc, CRIU and image storage. The model runners use local checkpoint directories
without archive export/import; the generic driver also supports archive mode.
`restore_to_first_token_us`
also includes memory resumption, readiness polling and the first inference.

Both backends use the same binary, plugin, image digest, model commit, request,
memory saver and compression settings. Each configuration has one excluded
warmup trial followed by N measured trials. Order rotates each round (AB, BA).
Downloading and model loading happen before checkpoint timing, but image page
cache residency is uncontrolled unless a separate cache policy is selected.
SGLang memory saver releases managed GPU allocations before checkpoint, matching the
snapshot lifecycle. CPU weight backup preserves model parameters in host memory,
which CRIU includes in its images and SGLang copies back to the GPU on resume.
Without that backup, release/resume discards the model weights. These results
include weight storage and transfer, but do not describe copying the full live
VRAM footprint. Use the same storage and GPU assignment for all trials.
The [VoiceChat runner](#nemotronlabs-voicechat-11b) instead measures the NVIDIA
speech server with live GPU state and a fixed audio recording.

SGLang runners serve offline. Before launching one, download its model into
`/root/.cache/huggingface/hub` using `hf download MODEL --revision REVISION
--cache-dir /root/.cache/huggingface/hub`; use the exact model and revision from
the corresponding section or the runner's `--help`. A missing file then fails
startup rather than triggering a download during the experiment. The runner-only
examples below assume this preparation is complete. VoiceChat uses a separately
prepared, local Triton repository as described below.

All model runners default to one measured trial per backend for a smoke test.
After that succeeds, set `ITERATIONS=4` or more for a comparison, for example:

```bash
sudo env ITERATIONS=4 ./contrib/compression-benchmark/run-qwen38-fp8-cuda-backends.sh
```

This runs one excluded warmup and four measured trials per backend (ten cycles
total). Four trials provide an initial view of variability, not a guarantee
that a small backend difference can be resolved. Keep raw samples and inspect
their spread; a single measured trial cannot establish a backend ranking.

## Minimal Qwen3.6-27B run

For the single-H200 evaluation, run the checked-in script from the checkout:

```bash
MODEL_REVISION=$(python3 - <<'PY'
import json
import urllib.request
with urllib.request.urlopen('https://huggingface.co/api/models/Qwen/Qwen3.6-27B') as response:
    print(json.load(response)['sha'])
PY
)
sudo hf download Qwen/Qwen3.6-27B --revision "$MODEL_REVISION" \
  --cache-dir /root/.cache/huggingface/hub
sudo env MODEL_REVISION="$MODEL_REVISION" \
  ./contrib/compression-benchmark/run-qwen36-cuda-backends.sh
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
and saves it, but offline startup still requires that commit to be cached.
Use `--help` for prerequisites. The script is intended to be run
by the user on the benchmark host; it does not connect over SSH itself.

### Qwen3.8-27B-FP8

Use the separate runner for
[Qwen3.8-27B-FP8](https://huggingface.co/Qwen/Qwen3.8-27B-FP8) on the benchmark
host after the previous benchmark finishes. It pins the model to revision
`017b9c7af6b5689d5dd426a76e0bc077eb5ca20a`:

```bash
cd /var/tmp/criu
# Populate the root user's cache before the offline benchmark.
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
allocations. Their CPU backups and checkpoint images will be larger than the
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

### NemotronLabs VoiceChat-11B

Use `run-voicechat-11b-cuda-backends.sh` for actual speech input and output with
[NVIDIA-NemotronLabs-VoiceChat-11B](https://huggingface.co/nvidia/NVIDIA-NemotronLabs-VoiceChat-11B/tree/a4c40ca5b4fe77db13e9840ca4a2b91becf030c8).
It runs NVIDIA's Triton/vLLM speech container through its realtime WebSocket API.
The runner checkpoints live CUDA state after closing the speech session; it
does not use the SGLang memory-saver endpoints. Compare the two backends within
this workload rather than comparing its times directly with the text runners.

Run the following commands yourself on the GPU host, from the CRIU checkout.
Use an idle H200, the common CRIU/Podman prerequisites below, and free ports
8000, 8001, 8002 and 9000. NVIDIA requires at least 80 GB of GPU memory for this
container. Prepare the model once, outside the benchmark, following NVIDIA's
[model-repository recipe](https://github.com/NVIDIA-NeMo/Speech/blob/097dfe9e2f55baf653b83035868bdc89849f1b47/voicechat_realtime_instructions/generate-model-repo.md).
The commands below replace its moving image and model references with the
same pins as the runner. Keep the variables in the same shell; change
`voicechat_work` to any writable absolute directory with enough space for the
original and converted weights.

```bash
cd /var/tmp/criu
set -euo pipefail
voicechat_work="$HOME/voicechat-benchmark"
mkdir -p "$voicechat_work"
voicechat_work=$(cd -- "$voicechat_work" && pwd)

# Ubuntu setup; the benchmark client runs in this virtual environment.
sudo apt-get install -y python3-venv ffmpeg
python3 -m venv "$voicechat_work/venv"
"$voicechat_work/venv/bin/python3" -m pip install \
  'websockets==15.0.1' 'huggingface-hub==0.34.4'

voicechat_revision='a4c40ca5b4fe77db13e9840ca4a2b91becf030c8'
voicechat_image='nvcr.io/nim/nvidia/nemotron-labs-voicechat'
voicechat_digest='6e69ff2aac955be2cb65b0de4f5b6d7c0b5e45ca0a1d42a2b153e9b54efb059b'
voicechat_checkpoint="$voicechat_work/hf-checkpoint"
voicechat_model_repo="$voicechat_work/model-repo"

"$voicechat_work/venv/bin/hf" download \
  nvidia/NVIDIA-NemotronLabs-VoiceChat-11B \
  --revision "$voicechat_revision" --local-dir "$voicechat_checkpoint"

# Use a new output directory: the converter skips files that already exist.
mkdir "$voicechat_model_repo"
sudo podman run --rm --user 0:0 --security-opt label=disable \
  --device nvidia.com/gpu=all --shm-size 8g \
  --volume "$voicechat_checkpoint:/checkpoint:ro" \
  --volume "$voicechat_model_repo:/data/models" \
  --env NEMO_CHECKPOINT_PATH=/checkpoint \
  --entrypoint /bin/bash "${voicechat_image}@sha256:${voicechat_digest}" \
  -c 'umask 022; exec /s2s/deploy_s2s_model.sh' \
  2>&1 | tee "$voicechat_work/conversion.log"

test -f "$voicechat_model_repo/nemotron-voicechat/config.pbtxt"
test -d "$voicechat_model_repo/nemotron-voicechat/1/tokenizer"
```

The input directory must include `config.json` and `rnnt_tokenizer/` as well as
`model.safetensors`; the full pinned download includes them. Conversion uses
the script bundled in the pinned image and may take minutes. It downloads a
separate tokenizer without pinning that tokenizer's revision. Consequently,
recreating the converted repository later is not guaranteed to be identical
from the model and image pins alone. Reuse the same converted directory for
both backends and future comparisons, retain `conversion.log`, and compare the
converted-file SHA-256 hashes recorded in `results.json`. The benchmark mounts
the directory read-only at `/data/models`, matching conversion's internal path.

Choose a short, clear English question that needs no tools. Replace the input
path below with your own recording, then convert it once to 24 kHz mono PCM16
WAV. Use that same file for every trial; the client automatically appends
20 seconds of silence to allow the model to respond.

```bash
voicechat_recording='/absolute/path/to/short-question.wav'
voicechat_audio="$voicechat_work/question-24k-pcm16.wav"
ffmpeg -n -i "$voicechat_recording" -vn -ac 1 -ar 24000 -c:a pcm_s16le \
  "$voicechat_audio"

# First run the minimum four-cycle smoke test.
sudo env PATH="$voicechat_work/venv/bin:$PATH" ITERATIONS=1 \
  ./contrib/compression-benchmark/run-voicechat-11b-cuda-backends.sh \
  "$voicechat_model_repo" "$voicechat_audio"

# After the smoke test passes, run four measured cycles per backend.
sudo env PATH="$voicechat_work/venv/bin:$PATH" ITERATIONS=4 \
  ./contrib/compression-benchmark/run-voicechat-11b-cuda-backends.sh \
  "$voicechat_model_repo" "$voicechat_audio"
```

The explicit `PATH` keeps `python3` in the virtual environment under `sudo`.
For an already converted repository or WAV elsewhere, set the two path
variables accordingly. A third positional argument selects a new results
directory; otherwise each invocation creates
`/var/tmp/voicechat-11b-cuda-backends.*` with `results.json`, `run.log`,
`model-revision.txt` and `speech/trial-*/` recordings, transcripts and protocol
events. Model hashing and container startup are outside checkpoint timing.

Validation requires completed responses, nonempty user and agent transcripts,
nonsilent output audio, and identical stripped input transcriptions before and
after restore. Generated speech and text hashes are retained for inspection;
the server's sampler is unseeded, so exact output equality is not required.
This checks restored speech functionality, not speech quality or determinism.
`restore_to_first_audio_packet_us` includes restore, health polling, session
setup and the beginning of the audio replay; the first packet can be silent.
Session-completion time additionally includes the recording and trailing silence.
Use checkpoint/restore and CUDA-hook timings for backend attribution. This
container's GPU startup and checkpoint/restore still need qualification on the
target host; only `status: complete` denotes a successful comparison run.

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
sudo hf download Qwen/Qwen3-0.6B --revision "$MODEL_REVISION" \
  --cache-dir /root/.cache/huggingface/hub
IMAGE='docker.io/lmsysorg/sglang:v0.5.17-cu130-runtime'
DIGEST='3ea7c6d74312d964edbcf9b3819425ea42117eb967ef1cfec632a70c926027df'
sudo env PATH="/var/tmp/criu/criu:$PATH" \
  python3 contrib/compression-benchmark/podman-sglang.py \
  --image "${IMAGE}@sha256:${DIGEST}" \
  --model Qwen/Qwen3-0.6B --model-revision "$MODEL_REVISION" \
  --criu-libdir /var/tmp/criu/plugins/cuda \
  --cuda-backends driver-api cuda-checkpoint \
  --modes uncompressed --checkpoint-storage local --archive-compression none \
  --sglang-arg=--disable-radix-cache \
  --offline --warmup-requests 2 --iterations 10 --print-stats \
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

### Storage and timing boundaries

`--checkpoint-storage local` restores the stopped container from Podman's local
checkpoint directory. It avoids exporting a tar archive, removing/recreating
the container, and importing the archive. Image I/O is still part of the
experiment; this option does not make storage costs disappear. The generic
drivers retain `--checkpoint-storage archive` for the export/import scenario.
Compare samples using the same storage mode and filesystem. New local-mode
results are not directly comparable with older archive-mode wall times.
`checkpoint_size_scope` identifies the size boundary: local mode counts CRIU
images only; archive mode counts the whole Podman archive, including metadata
and filesystem changes. `checkpoint_disk_bytes` records allocated storage, which
can differ from logical size for sparse files.

`--cache-policy uncontrolled` is the default: it records that no image-cache
preparation is performed. For a separate cold-cache experiment on a dedicated
idle host, use `--cache-policy cold`. This synchronizes pending writes and drops
the host page cache immediately before the restore timer starts; it affects
other workloads on the host. Keep the policy identical across backends and
report it explicitly. It does not define GPU cache or remote-storage cache state.

Treat the timing levels as nested measurements:

| Measurement | Interpretation |
| --- | --- |
| Podman command wall time | The requested checkpoint or restore operation, including runtime and storage work |
| OCI runtime time | The runtime's portion of that operation |
| CRIU stats | Specific CRIU phases, with boundaries defined by CRIU |
| CUDA plugin hook time | Backend work within the runtime/CRIU operation, including dispatch, helpers and state queries |
| Restore to validated output | Application recovery, including health checks, framework resume and inference |

`application_prepare_us` measures framework preparation before the checkpoint
command, and `application_resume_us` measures framework resumption after the
restore command. For SGLang these include its memory-saver calls and weight
resumption. They are outside the OCI command timings; resume is already inside
the restore-to-output measurement. VoiceChat has no corresponding framework
memory-release/resume calls.

Do not add CUDA times to OCI totals: those calls are already inside the
operation. CRIU's `restore_time` stops before the late CUDA resume hook, so it
does not cover the full CUDA restore path. The difference between OCI time and
CRIU stats also includes other work and cannot be labelled CUDA overhead.
Use phase measurements for attribution and whole-operation measurements for
the practical effect on the workload. Check instrumented versus uninstrumented
runs before interpreting a difference comparable to the logging overhead.
CUDA comparisons enable `--cuda-timings` by default and require corresponding
records in the retained CRIU logs. Use `--no-cuda-timings` with the generic
driver for the otherwise identical uninstrumented comparison. Both modes use
CRIU `verbosity 4` and verify the selected backend from the logs.

## Results and interpretation

`results.json` is updated atomically after every completed or failed trial.
It contains system information, executable SHA-256 hashes for CRIU, the plugin
and the required CUDA utilities, GPU UUID and driver version, runc version,
and the run arguments. `results` groups measured samples by configuration;
`warmups` contains the excluded warmup samples, and `failures` records failed
trials. Successful samples include their `trial` number and `configuration`,
so trial order can be reconstructed across the groups. Checkpoint wall time,
restore wall time and restore-to-first-token time are in microseconds.
The console report includes medians, minimum/maximum values and sample counts.
Retain the raw samples as well.

With exactly two configurations, it also pairs OCI checkpoint and restore
measurements from the same round using their global trial numbers. Differences
are the second listed configuration minus the first: positive values mean the
first was faster in that pair. Missing measurements do not shift later pairs.
Each metric is labelled inconclusive if fewer than four complete pairs exist
or if the paired difference range includes zero. A consistent direction in four
or more observed pairs is still not a statistical-significance claim; examine
variability and repeat before concluding that a small difference is reproducible.

Only use a file with `status: complete` as a completed run. A single measured
sample remains a smoke test even when validation succeeds. Errors are recorded
with the failed configuration and artifact directory; no failed trial is added
to successful timing samples. Investigate mismatches before making performance
claims, and keep failed runs alongside successful runs.

Small diagnostics persist after container cleanup. For `--json
/path/results.json`, the default directory is `/path/results.artifacts`;
`--artifacts-dir` overrides it. Each `trial-N/` contains progress and validation
records, with `checkpoint/` and `restore/` subdirectories for CRIU logs/stats,
Podman output/stats and container state. VoiceChat selects the results
directory's `speech/` subdirectory and additionally retains the input WAV and
before/after speech artifacts. Missing diagnostics after an early failure are
not evidence that the corresponding phase succeeded. Large checkpoint images
are retained only with `--keep-checkpoint-files`; plan disk capacity separately
from retaining logs and JSON.

The difference between backend wall-time distributions estimates their impact
on this workload. It is not absolute plugin overhead versus no plugin (a real
CUDA workload needs checkpoint support), and overlapping distributions may not
resolve a small difference. Report sample count, spread, order, cache/storage
policy and failures with any backend comparison. A label such as "warm" must
describe a performed cache preparation step, not an assumption based on model
startup. Neither local storage nor an excluded warmup guarantees resident image
pages when the workload and its checkpoint compete for host RAM.

Local verification (no GPU or container launch):

```bash
make -C test/others/compression/benchmark unit
make -C plugins/cuda ARCH=x86
make -C test/cuda-checkpoint cuda-plugin-timings-test
./test/cuda-checkpoint/cuda-plugin-timings-test
```
