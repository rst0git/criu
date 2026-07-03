# Large private VMA restore benchmark

`bench-large-restore.sh` measures dump and restore time for a dense private
anonymous mapping. The workload maps a configurable amount of memory, touches
one byte per page, asks CRIU to dump and restore it, and verifies the touched
bytes after restore.

The default mapping size is 4096 MiB. This is intended to exercise large
private VMA restore behavior, not to be part of routine ZDTM coverage.

## Build

Build CRIU first if the binary is stale:

```sh
make -j"$(nproc)" criu/criu
```

The benchmark script builds `test/zdtm/static/maps04-bench` automatically.

## Run

Run with an explicit image directory and report path:

```sh
sudo -n ./test/others/mem-snap/bench-large-restore.sh \
	-n 3 \
	--criu ./criu/criu \
	--img-dir /tmp/criu-large-restore-bench \
	--output /tmp/criu-large-restore-bench/report.log
```

The script runs CRIU with `--no-default-config` for both dump and restore so
host defaults do not silently change the measured path.

Useful options:

```text
-m, --mem-size-mb N    mapping size in MiB, default 4096
-n, --iterations N     number of measured iterations, default 1
--criu PATH            CRIU binary to benchmark
--variant LABEL=PATH   add a CRIU binary variant; repeat to compare variants
--img-dir PATH         directory for CRIU images and logs
--output PATH          full report path
--summary PATH         readable Markdown summary path
--results-csv PATH     concise CSV results path
--keep-img             keep per-iteration image directories
```

The terminal output is CSV:

```csv
variant,iteration,mem_mib,dump_ms,restore_ms,restore_time_us,pages_restored,nr_enqueued,forced_premap_count,large_remap_count,path_hint
criu,1,4096,1984,1765,1760849,1048606,16,1,1,large-premap
```

The same CSV is saved to `results.csv` next to the full report unless
`--results-csv` is specified.

## Read the results

Start with the readable Markdown summary:

```sh
less /tmp/criu-large-restore-bench/summary.md
```

Read the raw CSV:

```sh
column -s, -t /tmp/criu-large-restore-bench/results.csv | less -S
```

Open the full debug report when the summary is not enough:

```sh
less /tmp/criu-large-restore-bench/report.log
```

For a quick summary:

```sh
grep -E 'Version:|GitID:|restore_time|pages_restored|Force premap|large restorer IO|nr_enqueued|results csv|summary' \
	/tmp/criu-large-restore-bench/report.log
```

Important files:

```text
summary.md
```

Human-readable configuration, per-variant timing summaries, per-iteration
results, and restore-path evidence.

```text
results.csv
```

Concise machine-readable result rows. The most important fields are
`restore_ms`, `restore_time_us`, `nr_enqueued`, `forced_premap_count`,
`large_remap_count`, and `path_hint`.

```text
report.log
```

Complete system information, CRIU stats, restore markers, workload output, and
full CRIU dump/restore logs.

Important report sections:

```text
## Benchmark configuration
```

Records the command line, CRIU binary, image directory, mapping size, iteration
count, and exact dump/restore arguments.

```text
## uname
## cpu
## memory
## filesystem
## vm-settings
## transparent huge pages
```

Records host details that can affect restore time.

```text
## criu-version
## criu-file
## git
```

Records the CRIU binary version, file metadata, capabilities, and source tree
state used for the run.

```text
## variant LABEL iteration N stats-dump
## variant LABEL iteration N stats-restore
```

Contains CRIU internal statistics from `stats-dump` and `stats-restore`.
`restore_time` is in microseconds.

```text
## variant LABEL iteration N restore path markers
```

Shows the relevant restore log lines. For the large-VMA premap path, expect
markers like:

```text
Force premap ... large restorer IO
Remap ... len 0x100000000
Restore finished successfully
```

If the large VMA is restored from the restorer instead, expect a large
`nr_enqueued` value and no `Force premap ... large restorer IO` marker.

```text
## results csv
## summary
```

Contains the same CSV and aggregate statistics that are also summarized in
`summary.md`.

## Reproduce restorer-vs-premap comparison

To reproduce a restorer-vs-premap experiment, build two CRIU binaries:

1. `restorer`: the baseline tree without the `false &&` change.
2. `forced-premap`: the same baseline tree with the temporary `false &&`
   change in `premap_priv_vmas()`.

Then pass both binaries as variants in a single benchmark run:

```sh
sudo -n ./test/others/mem-snap/bench-large-restore.sh \
	-n 5 \
	--variant restorer=/path/to/restorer/criu \
	--variant forced-premap=/path/to/forced-premap/criu \
	--img-dir /tmp/criu-large-restore-compare \
	--output /tmp/criu-large-restore-compare/report.log
```

Compare both variants in `summary.md` first, then inspect `results.csv` and
`## variant LABEL iteration N stats-restore` in `report.log` if more detail is
needed. The script times include process startup and CRIU command overhead;
CRIU `restore_time` is the internal restore statistic.

The baseline restorer path should have no `Force premap ... large restorer IO`
marker and should show a large `nr_enqueued` value. The forced premap path
should show `Force premap ... large restorer IO` or many premap/remap markers,
depending on the exact CRIU tree being tested.

## Recent local result

The following result was captured on the `mem-benchmark` branch with the
current large-premap CRIU binary on a Fedora 44 host with Linux
`7.0.14-201.fc44.x86_64`, an Intel Core Ultra 9 275HX, 24 CPUs, 188 GiB of
RAM, and a btrfs NVMe filesystem.

Command:

```sh
sudo -n ./test/others/mem-snap/bench-large-restore.sh \
	-n 10 \
	--criu ./criu/criu \
	--img-dir ./test/others/mem-snap/dump/large-restore-report-10 \
	--output ./test/others/mem-snap/dump/large-restore-report-10/report.log
```

CSV output:

```csv
variant,iteration,mem_mib,dump_ms,restore_ms,restore_time_us,pages_restored,nr_enqueued,forced_premap_count,large_remap_count,path_hint
criu,1,4096,1984,1765,1760849,1048606,16,1,1,large-premap
criu,2,4096,2000,1795,1791338,1048607,15,1,1,large-premap
criu,3,4096,1971,1805,1800801,1048606,15,1,1,large-premap
criu,4,4096,1957,1766,1761286,1048608,16,1,1,large-premap
criu,5,4096,2005,1773,1769155,1048606,16,1,1,large-premap
criu,6,4096,2010,1804,1800153,1048606,15,1,1,large-premap
criu,7,4096,1970,1795,1791188,1048608,15,1,1,large-premap
criu,8,4096,1994,1859,1854560,1048607,15,1,1,large-premap
criu,9,4096,1983,1781,1777073,1048606,15,1,1,large-premap
criu,10,4096,1997,1765,1761193,1048608,15,1,1,large-premap
```

Script timing summary:

```text
variant=criu
dump_ms_count=10
dump_ms_mean=1987.100
dump_ms_median=1989.000
dump_ms_min=1957
dump_ms_max=2010
restore_ms_count=10
restore_ms_mean=1790.800
restore_ms_median=1788.000
restore_ms_min=1765
restore_ms_max=1859
```

CRIU internal restore stats:

```text
restore_time_us_count=10
restore_time_us_mean=1786759.600
restore_time_us_median=1784130.500
restore_time_us_min=1760849
restore_time_us_max=1854560
```

All iterations restored the 4096 MiB VMA through the intended path. Each
iteration reported restore markers like:

```text
Force premap ... large restorer IO
Remap ... len 0x100000000
Restore finished successfully
```

## Generated files

The default generated files live under `test/others/mem-snap/dump/`, which is
ignored by Git. Use `--keep-img` only when the CRIU image files and logs are
needed for debugging; otherwise the script removes each per-iteration image
directory after writing the report.
