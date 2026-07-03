#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

source "${SCRIPT_DIR}/../env.sh" || exit 1

MEM_SIZE_MB=4096
ITERATIONS=1
IMGDIR="${SCRIPT_DIR}/dump/large-restore-bench"
OUTPUT=
SUMMARY_FILE=
RESULTS_CSV=
KEEP_IMG=0
CURRENT_PID=
START_TIME_LOCAL=
START_TIME_UTC=
ORIGINAL_ARGS=("$@")
declare -a VARIANT_LABELS=()
declare -a VARIANT_CRIUS=()

format_help_path()
{
	local path="$1"

	case "${path}" in
	"${BASE_DIR}"/*)
		printf ".%s" "${path#"${BASE_DIR}"}"
		;;
	*)
		printf "%s" "${path}"
		;;
	esac
}

usage()
{
	cat <<EOF
Usage: $0 [OPTIONS]

Benchmark restoring a dense private anonymous VMA.

Options:
  -m, --mem-size-mb N    Mapping size in MiB (default: ${MEM_SIZE_MB})
  -n, --iterations N     Number of measured iterations (default: ${ITERATIONS})
      --criu PATH        CRIU binary to benchmark (default: $(format_help_path "${CRIU}"))
      --variant LABEL=PATH
                         Add a CRIU binary variant to compare. Repeat this
                         option to reproduce a restorer-vs-premap
                         experiment in one run.
      --img-dir PATH     Directory for images and logs (default: $(format_help_path "${IMGDIR}"))
      --output PATH      Save full report to PATH
                         (default: IMGDIR/bench-large-restore-<timestamp>.log)
      --summary PATH     Save readable Markdown summary to PATH
                         (default: OUTPUT directory/summary.md)
      --results-csv PATH Save concise CSV results to PATH
                         (default: OUTPUT directory/results.csv)
      --keep-img         Keep per-iteration image directories
  -h, --help             Show this help
EOF
}

fail()
{
	echo "$@" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	-m|--mem-size-mb)
		MEM_SIZE_MB="$2"
		shift 2
		;;
	-n|--iterations)
		ITERATIONS="$2"
		shift 2
		;;
	--criu)
		CRIU="$2"
		shift 2
		;;
	--variant)
		case "$2" in
		*=*)
			label="${2%%=*}"
			criu_path="${2#*=}"
			[ -n "${label}" ] || fail "Variant label must not be empty"
			[ -n "${criu_path}" ] || fail "Variant CRIU path must not be empty"
			case "${label}" in
			*,*)
				fail "Variant label must not contain ',': ${label}"
				;;
			esac
			VARIANT_LABELS+=("${label}")
			VARIANT_CRIUS+=("${criu_path}")
			shift 2
			;;
		*)
			fail "Invalid variant, expected LABEL=PATH: $2"
			;;
		esac
		;;
	--img-dir)
		IMGDIR="$2"
		shift 2
		;;
	--output)
		OUTPUT="$2"
		shift 2
		;;
	--summary)
		SUMMARY_FILE="$2"
		shift 2
		;;
	--results-csv)
		RESULTS_CSV="$2"
		shift 2
		;;
	--keep-img)
		KEEP_IMG=1
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		fail "Unknown option: $1"
		;;
	esac
done

case "$MEM_SIZE_MB" in
''|*[!0-9]*)
	fail "Invalid memory size: ${MEM_SIZE_MB}"
	;;
esac

case "$ITERATIONS" in
''|*[!0-9]*)
	fail "Invalid iteration count: ${ITERATIONS}"
	;;
esac

[ "$MEM_SIZE_MB" -gt 0 ] || fail "Memory size must be greater than zero"
[ "$ITERATIONS" -gt 0 ] || fail "Iteration count must be greater than zero"

if [ "${#VARIANT_LABELS[@]}" -eq 0 ]; then
	VARIANT_LABELS=("criu")
	VARIANT_CRIUS=("${CRIU}")
fi

for i in "${!VARIANT_CRIUS[@]}"; do
	[ -x "${VARIANT_CRIUS[${i}]}" ] ||
		fail "CRIU binary is not executable for variant ${VARIANT_LABELS[${i}]}: ${VARIANT_CRIUS[${i}]}"
	for j in "${!VARIANT_LABELS[@]}"; do
		if [ "${i}" -lt "${j}" ] && [ "${VARIANT_LABELS[${i}]}" = "${VARIANT_LABELS[${j}]}" ]; then
			fail "Duplicate variant label: ${VARIANT_LABELS[${i}]}"
		fi
	done
done

ZDTM_DIR="${BASE_DIR}/test/zdtm/static"
PIDFILE="${ZDTM_DIR}/maps04-bench.pid"
OUTFILE="${ZDTM_DIR}/maps04-bench.out"

shell_quote_args()
{
	local arg

	for arg in "$@"; do
		printf " %q" "${arg}"
	done
}

sanitize_label()
{
	printf "%s" "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

report_section()
{
	printf "\n## %s\n\n" "$1" >> "${OUTPUT}"
}

report_cmd()
{
	local title="$1"
	local ret

	shift
	report_section "${title}"
	{
		printf "$"
		shell_quote_args "$@"
		printf "\n"
		set +e
		"$@"
		ret=$?
		set -e
		if [ "${ret}" -ne 0 ]; then
			printf "[command exited with %d]\n" "${ret}"
		fi
	} >> "${OUTPUT}" 2>&1
}

report_file()
{
	local file="$1"

	report_section "${file}"
	if [ -r "${file}" ]; then
		cat "${file}" >> "${OUTPUT}"
	else
		printf "[file is not readable or does not exist]\n" >> "${OUTPUT}"
	fi
}

report_sysfs_file()
{
	local file="$1"

	if [ -r "${file}" ]; then
		printf "%s: " "${file}" >> "${OUTPUT}"
		cat "${file}" >> "${OUTPUT}"
	fi
}

crit_field()
{
	local file="$1"
	local key="$2"

	${CRIT} show "${file}" 2>/dev/null |
		awk -v key="\"${key}\"" '
			index($0, key ":") {
				sub(/.*: /, "");
				sub(/,.*/, "");
				gsub(/[ "]/, "");
				print;
				exit;
			}'
}

grep_count()
{
	local pattern="$1"
	local file="$2"

	grep -cE "${pattern}" "${file}" 2>/dev/null || true
}

restore_nr_enqueued()
{
	local file="$1"

	awk '/nr_enqueued:/ { print $NF; exit }' "${file}" 2>/dev/null || true
}

restore_path_hint()
{
	local nr_enqueued="$1"
	local forced_premap_count="$2"
	local large_remap_count="$3"

	if [ "${forced_premap_count:-0}" -gt 0 ]; then
		printf "large-premap"
	elif [ "${large_remap_count:-0}" -gt 0 ]; then
		printf "forced-premap"
	elif [ -n "${nr_enqueued}" ] && [ "${nr_enqueued}" -gt 100 ]; then
		printf "restorer-io"
	else
		printf "unknown"
	fi
}

append_result_row()
{
	local variant_label="$1"
	local iteration="$2"
	local dump_ms="$3"
	local restore_ms="$4"
	local rundir="$5"
	local map_len_hex
	local restore_time_us
	local pages_restored
	local nr_enqueued
	local forced_premap_count
	local large_remap_count
	local path_hint

	map_len_hex=$(printf "%x" "$((MEM_SIZE_MB * 1024 * 1024))")
	restore_time_us=$(crit_field "${rundir}/stats-restore" restore_time)
	pages_restored=$(crit_field "${rundir}/stats-restore" pages_restored)
	nr_enqueued=$(restore_nr_enqueued "${rundir}/restore.log")
	forced_premap_count=$(grep_count "Force premap.*large restorer IO" "${rundir}/restore.log")
	large_remap_count=$(grep_count "Remap 0x.* len 0x${map_len_hex}" "${rundir}/restore.log")
	path_hint=$(restore_path_hint "${nr_enqueued}" "${forced_premap_count}" "${large_remap_count}")

	printf "%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
		"${variant_label}" "${iteration}" "${MEM_SIZE_MB}" "${dump_ms}" "${restore_ms}" \
		"${restore_time_us:-}" "${pages_restored:-}" "${nr_enqueued:-}" \
		"${forced_premap_count}" "${large_remap_count}" "${path_hint}" |
		tee -a "${RESULTS_CSV}"
}

write_metric_summary_row()
{
	local variant="$1"
	local metric="$2"
	local col="$3"
	local unit="$4"
	local values=()
	local count
	local sum
	local min
	local max
	local median
	local i
	local mid

	mapfile -t values < <(awk -F, -v variant="${variant}" -v col="${col}" \
		'NR > 1 && $1 == variant && $col != "" { print $col }' "${RESULTS_CSV}" | sort -n)
	count=${#values[@]}
	[ "${count}" -gt 0 ] || return 0

	sum=0
	min=${values[0]}
	max=${values[$((count - 1))]}
	for i in "${values[@]}"; do
		sum=$((sum + i))
	done

	mid=$((count / 2))
	if [ $((count % 2)) -eq 1 ]; then
		median=${values[${mid}]}
	else
		median=$(awk -v a="${values[$((mid - 1))]}" -v b="${values[${mid}]}" \
			'BEGIN { printf "%.3f", (a + b) / 2 }')
	fi

	awk -v variant="${variant}" -v metric="${metric}" -v unit="${unit}" \
		-v count="${count}" -v sum="${sum}" -v min="${min}" \
		-v median="${median}" -v max="${max}" \
		'BEGIN {
			printf "| %s | %s | %s | %d | %.3f | %s | %s | %s |\n",
				variant, metric, unit, count, sum / count, median, min, max;
		}'
}

write_markdown_summary()
{
	local i
	local variant

	{
		printf "# Large Restore Benchmark Summary\n\n"
		printf "| Field | Value |\n"
		printf "| --- | --- |\n"
		printf "| Start time | %s |\n" "${START_TIME_LOCAL}"
		printf "| Memory size | %s MiB |\n" "${MEM_SIZE_MB}"
		printf "| Iterations | %s |\n" "${ITERATIONS}"
		printf "| Full report | \`%s\` |\n" "${OUTPUT}"
		printf "| Results CSV | \`%s\` |\n" "${RESULTS_CSV}"
		printf "| Variants | %s |\n\n" "${#VARIANT_LABELS[@]}"

		printf "## Variants\n\n"
		printf "| Variant | CRIU binary |\n"
		printf "| --- | --- |\n"
		for i in "${!VARIANT_LABELS[@]}"; do
			printf "| %s | \`%s\` |\n" "${VARIANT_LABELS[${i}]}" "${VARIANT_CRIUS[${i}]}"
		done

		printf "\n## Timing Summary\n\n"
		printf "| Variant | Metric | Unit | Count | Mean | Median | Min | Max |\n"
		printf "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |\n"
		for variant in "${VARIANT_LABELS[@]}"; do
			write_metric_summary_row "${variant}" dump_ms 4 ms
			write_metric_summary_row "${variant}" restore_ms 5 ms
			write_metric_summary_row "${variant}" criu_restore_time 6 us
		done

		printf "\n## Per-Iteration Results\n\n"
		printf "| Variant | Iteration | Mem MiB | Dump ms | Restore ms | CRIU restore us | Pages restored | Path |\n"
		printf "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n"
		awk -F, 'NR > 1 {
			printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				$1, $2, $3, $4, $5, $6, $7, $11;
		}' "${RESULTS_CSV}"

		printf "\n## Restore Path Evidence\n\n"
		printf "| Variant | Iteration | nr_enqueued | Force premap markers | Large remaps | Path hint |\n"
		printf "| --- | ---: | ---: | ---: | ---: | --- |\n"
		awk -F, 'NR > 1 {
			printf "| %s | %s | %s | %s | %s | %s |\n",
				$1, $2, $8, $9, $10, $11;
		}' "${RESULTS_CSV}"
	} > "${SUMMARY_FILE}"
}

write_system_report()
{
	local i

	report_section "Benchmark configuration"
	{
		printf "start_time_local=%s\n" "${START_TIME_LOCAL}"
		printf "start_time_utc=%s\n" "${START_TIME_UTC}"
		printf "script=%s\n" "$0"
		printf "command_line=%q" "$0"
		shell_quote_args "${ORIGINAL_ARGS[@]}"
		printf "\n"
		printf "base_dir=%s\n" "${BASE_DIR}"
		printf "img_dir=%s\n" "${IMGDIR}"
		printf "output=%s\n" "${OUTPUT}"
		printf "summary=%s\n" "${SUMMARY_FILE}"
		printf "results_csv=%s\n" "${RESULTS_CSV}"
		printf "mem_size_mb=%s\n" "${MEM_SIZE_MB}"
		printf "iterations=%s\n" "${ITERATIONS}"
		printf "keep_img=%s\n" "${KEEP_IMG}"
		printf "variants=%s\n" "${#VARIANT_LABELS[@]}"
		for i in "${!VARIANT_LABELS[@]}"; do
			printf "variant_%s_label=%s\n" "${i}" "${VARIANT_LABELS[${i}]}"
			printf "variant_%s_criu=%s\n" "${i}" "${VARIANT_CRIUS[${i}]}"
			printf "variant_%s_criu_realpath=%s\n" "${i}" \
				"$(readlink -f "${VARIANT_CRIUS[${i}]}" 2>/dev/null || printf "%s" "${VARIANT_CRIUS[${i}]}")"
		done
		printf "dump_args=--no-default-config -D RUNDIR -o dump.log -t PID -v4\n"
		printf "restore_args=--no-default-config -D RUNDIR -o restore.log -d -v4\n"
	} >> "${OUTPUT}"

	report_cmd "uname" uname -a
	report_cmd "id" id
	report_cmd "limits" sh -c "ulimit -a"
	report_cmd "os-release" sh -c "cat /etc/os-release 2>/dev/null || true"
	report_cmd "kernel-cmdline" sh -c "cat /proc/cmdline 2>/dev/null || true"
	report_cmd "cpu" sh -c "lscpu 2>/dev/null || cat /proc/cpuinfo"
	report_cmd "memory" sh -c "free -h 2>/dev/null || true; echo; cat /proc/meminfo 2>/dev/null || true"
	report_cmd "numa" sh -c "numactl --hardware 2>/dev/null || true"
	report_cmd "page-size" getconf PAGE_SIZE
	report_cmd "word-size" getconf LONG_BIT
	report_cmd "filesystem" sh -c \
		"df -hT \"\$1\"; echo; findmnt -T \"\$1\" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true; echo; stat -f \"\$1\"" \
		sh "${IMGDIR}"
	report_cmd "vm-settings" sh -c \
		"sysctl vm.overcommit_memory vm.overcommit_ratio vm.swappiness vm.dirty_background_bytes vm.dirty_background_ratio vm.dirty_bytes vm.dirty_ratio 2>/dev/null || true"
	report_section "transparent huge pages"
	report_sysfs_file /sys/kernel/mm/transparent_hugepage/enabled
	report_sysfs_file /sys/kernel/mm/transparent_hugepage/defrag
	report_sysfs_file /sys/kernel/mm/transparent_hugepage/shmem_enabled
	for i in "${!VARIANT_LABELS[@]}"; do
		report_cmd "criu-version ${VARIANT_LABELS[${i}]}" "${VARIANT_CRIUS[${i}]}" --version
		report_cmd "criu-file ${VARIANT_LABELS[${i}]}" sh -c \
			"ls -l \"\$1\"; getcap \"\$1\" 2>/dev/null || true" \
			sh "${VARIANT_CRIUS[${i}]}"
	done
	report_cmd "git" sh -c \
		"git -C \"\$1\" rev-parse --abbrev-ref HEAD 2>/dev/null; git -C \"\$1\" rev-parse HEAD 2>/dev/null; git -C \"\$1\" status --short 2>/dev/null" \
		sh "${BASE_DIR}"
}

write_iteration_report()
{
	local variant_label="$1"
	local criu_path="$2"
	local iteration="$3"
	local rundir="$4"
	local dump_ms="$5"
	local restore_ms="$6"
	local target_pid="$7"

	report_section "variant ${variant_label} iteration ${iteration}"
	{
		printf "variant=%s\n" "${variant_label}"
		printf "criu=%s\n" "${criu_path}"
		printf "iteration=%s\n" "${iteration}"
		printf "mem_mib=%s\n" "${MEM_SIZE_MB}"
		printf "dump_ms=%s\n" "${dump_ms}"
		printf "restore_ms=%s\n" "${restore_ms}"
		printf "target_pid=%s\n" "${target_pid}"
		printf "rundir=%s\n" "${rundir}"
		printf "pidfile=%s\n" "${PIDFILE}"
		printf "outfile=%s\n" "${OUTFILE}"
		printf "dump_command=%q" "${criu_path}"
		shell_quote_args dump --no-default-config -D "${rundir}" -o dump.log -t "${target_pid}" -v4
		printf "\n"
		printf "restore_command=%q" "${criu_path}"
		shell_quote_args restore --no-default-config -D "${rundir}" -o restore.log -d -v4
		printf "\n"
	} >> "${OUTPUT}"

	if [ -r "${rundir}/stats-dump" ]; then
		report_cmd "variant ${variant_label} iteration ${iteration} stats-dump" \
			${CRIT} show "${rundir}/stats-dump"
	fi
	if [ -r "${rundir}/stats-restore" ]; then
		report_cmd "variant ${variant_label} iteration ${iteration} stats-restore" \
			${CRIT} show "${rundir}/stats-restore"
	fi

	report_cmd "variant ${variant_label} iteration ${iteration} restore path markers" sh -c \
		"grep -nE 'Force premap|large restorer IO|nr_enqueued|premap|Remap 0x.*len 0x100000000|Switched to the restorer|Restore finished successfully' \"\$1\" 2>/dev/null || true" \
		sh "${rundir}/restore.log"
	report_file "${OUTFILE}"
	report_file "${rundir}/dump.log"
	report_file "${rundir}/restore.log"
}

write_summary_report()
{
	local variant
	local label
	local col
	local values=()
	local count
	local sum
	local min
	local max
	local median
	local i
	local mid

	report_section "results csv"
	cat "${RESULTS_CSV}" >> "${OUTPUT}"

	report_section "summary"
	for variant in "${VARIANT_LABELS[@]}"; do
		printf "variant=%s\n" "${variant}" >> "${OUTPUT}"
		for label in dump_ms restore_ms; do
			case "${label}" in
			dump_ms)
				col=4
				;;
			restore_ms)
				col=5
				;;
			esac

			mapfile -t values < <(awk -F, -v variant="${variant}" -v col="${col}" \
				'NR > 1 && $1 == variant { print $col }' "${RESULTS_CSV}" | sort -n)
			count=${#values[@]}
			[ "${count}" -gt 0 ] || continue

			sum=0
			min=${values[0]}
			max=${values[$((count - 1))]}
			for i in "${values[@]}"; do
				sum=$((sum + i))
			done

			mid=$((count / 2))
			if [ $((count % 2)) -eq 1 ]; then
				median=${values[${mid}]}
			else
				median=$(awk -v a="${values[$((mid - 1))]}" -v b="${values[${mid}]}" \
					'BEGIN { printf "%.3f", (a + b) / 2 }')
			fi

			awk -v label="${label}" -v count="${count}" -v sum="${sum}" \
				-v min="${min}" -v median="${median}" -v max="${max}" \
				'BEGIN {
					printf "%s_count=%d\n", label, count;
					printf "%s_mean=%.3f\n", label, sum / count;
					printf "%s_median=%s\n", label, median;
					printf "%s_min=%s\n", label, min;
					printf "%s_max=%s\n", label, max;
				}' >> "${OUTPUT}"
		done
		printf "\n" >> "${OUTPUT}"
	done
}

cleanup()
{
	local pid
	local i

	if [ -n "${CURRENT_PID}" ]; then
		kill -TERM "${CURRENT_PID}" 2>/dev/null || true
		for i in $(seq 1 30); do
			kill -0 "${CURRENT_PID}" 2>/dev/null || break
			sleep 1
		done
	fi

	if [ -r "${PIDFILE}" ]; then
		pid=$(cat "${PIDFILE}" 2>/dev/null || true)
		if [ -n "${pid}" ]; then
			kill -TERM "${pid}" 2>/dev/null || true
		fi
	fi

}

trap cleanup EXIT

run_timed()
{
	local start
	local end
	local ret

	start=$(date +%s%N)
	set +e
	"$@"
	ret=$?
	set -e
	end=$(date +%s%N)
	ELAPSED_MS=$(((end - start) / 1000000))
	return "${ret}"
}

start_workload()
{
	rm -f "${PIDFILE}" "${OUTFILE}" "${OUTFILE}.inprogress"

	(
		cd "${ZDTM_DIR}"
		./maps04-bench \
			--pidfile=maps04-bench.pid \
			--outfile=maps04-bench.out \
			--mem_size_mb="${MEM_SIZE_MB}"
	)

	CURRENT_PID=$(cat "${PIDFILE}")
	kill -0 "${CURRENT_PID}" || fail "Benchmark workload did not start"
}

stop_workload()
{
	make -C "${ZDTM_DIR}" maps04-bench.stop >/dev/null
	grep -q PASS "${OUTFILE}" || fail "Benchmark workload failed"
	CURRENT_PID=
}

make -C "${ZDTM_DIR}" maps04-bench >/dev/null
mkdir -p "${IMGDIR}"

START_TIME_LOCAL=$(date -Is)
START_TIME_UTC=$(date -u -Is)

if [ -z "${OUTPUT}" ]; then
	OUTPUT="${IMGDIR}/bench-large-restore-$(date +%Y%m%d-%H%M%S).log"
fi

mkdir -p "$(dirname "${OUTPUT}")"
if [ -z "${RESULTS_CSV}" ]; then
	RESULTS_CSV="$(dirname "${OUTPUT}")/results.csv"
fi
if [ -z "${SUMMARY_FILE}" ]; then
	SUMMARY_FILE="$(dirname "${OUTPUT}")/summary.md"
fi
mkdir -p "$(dirname "${RESULTS_CSV}")" "$(dirname "${SUMMARY_FILE}")"

: > "${OUTPUT}"
: > "${RESULTS_CSV}"
: > "${SUMMARY_FILE}"

write_system_report

printf "variant,iteration,mem_mib,dump_ms,restore_ms,restore_time_us,pages_restored,nr_enqueued,forced_premap_count,large_remap_count,path_hint\n" |
	tee "${RESULTS_CSV}"

for variant_index in "${!VARIANT_LABELS[@]}"; do
	variant_label="${VARIANT_LABELS[${variant_index}]}"
	variant_criu="${VARIANT_CRIUS[${variant_index}]}"
	variant_dir=$(sanitize_label "${variant_label}")

	for i in $(seq 1 "${ITERATIONS}"); do
		RUNDIR="${IMGDIR}/${variant_dir}/${i}"

		rm -rf "${RUNDIR}"
		mkdir -p "${RUNDIR}"

		start_workload
		workload_pid="${CURRENT_PID}"

		if ! run_timed "${variant_criu}" dump --no-default-config -D "${RUNDIR}" -o dump.log -t "${CURRENT_PID}" -v4; then
			write_iteration_report "${variant_label}" "${variant_criu}" "${i}" "${RUNDIR}" \
				"${ELAPSED_MS}" "failed" "${workload_pid}"
			fail "CRIU dump failed for variant ${variant_label}"
		fi
		dump_ms="${ELAPSED_MS}"

		if ! run_timed "${variant_criu}" restore --no-default-config -D "${RUNDIR}" -o restore.log -d -v4; then
			write_iteration_report "${variant_label}" "${variant_criu}" "${i}" "${RUNDIR}" \
				"${dump_ms}" "${ELAPSED_MS}" "${workload_pid}"
			fail "CRIU restore failed for variant ${variant_label}"
		fi
		restore_ms="${ELAPSED_MS}"

		stop_workload

		append_result_row "${variant_label}" "${i}" "${dump_ms}" "${restore_ms}" "${RUNDIR}"
		write_iteration_report "${variant_label}" "${variant_criu}" "${i}" "${RUNDIR}" \
			"${dump_ms}" "${restore_ms}" "${workload_pid}"

		if [ "${KEEP_IMG}" -eq 0 ]; then
			rm -rf "${RUNDIR}"
		fi
	done
done

write_summary_report
write_markdown_summary
printf "Results CSV written to %s\n" "${RESULTS_CSV}" >&2
printf "Summary written to %s\n" "${SUMMARY_FILE}" >&2
printf "Full report written to %s\n" "${OUTPUT}" >&2
