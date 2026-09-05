#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage:
  scripts/bench-compare.sh <baseline-ref> <candidate-ref>
  scripts/bench-compare.sh --files <baseline-benchmark.txt> <candidate-benchmark.txt>

Ref mode creates temporary detached worktrees and runs the common decoder
benchmarks. File mode compares existing `go test -benchmem` output files.
EOF
}

if [[ $# -eq 0 ]]; then
	usage
	exit 2
fi

benchstat_bin=$(command -v benchstat || true)
if [[ -z "$benchstat_bin" || ! -x "$benchstat_bin" ]]; then
	echo "bench-compare: benchstat is required but was not found on PATH; install it separately (no automatic downloads)" >&2
	exit 1
fi

# Validate the stable rows before invoking benchstat. A benchmark name may have
# Go's optional GOMAXPROCS suffix (for example, -8), but a row still needs the
# usual benchmark iteration count and ns/op measurement to be usable.
validate_benchmark_file() {
	local file=$1
	[[ -f "$file" && -r "$file" ]] || { echo "bench-compare: benchmark file is not readable: $file" >&2; return 1; }
	awk -v file="$file" '
	function number(value) {
		return value ~ /^[0-9]+([.][0-9]*)?([eE][+-]?[0-9]+)?$/ || value ~ /^[.][0-9]+([eE][+-]?[0-9]+)?$/
	}
	function required_like(value, base) {
		return value == base || value ~ ("^" base "-.*$")
	}
	function valid_row(value, base) {
		return value == base || value ~ ("^" base "-[0-9]+$")
	}
	{
		if (required_like($1, "BenchmarkDecodeQuery")) {
			if (valid_row($1, "BenchmarkDecodeQuery") && NF >= 4 && $2 ~ /^[0-9]+$/ && $2 > 0 && number($3) && $4 == "ns/op") query++
			else query_bad++
		}
		if (required_like($1, "BenchmarkDecodeJSON")) {
			if (valid_row($1, "BenchmarkDecodeJSON") && NF >= 4 && $2 ~ /^[0-9]+$/ && $2 > 0 && number($3) && $4 == "ns/op") json++
			else json_bad++
		}
	}
	END {
		failed = 0
		if (query_bad || query < 10) {
			printf "bench-compare: %s: BenchmarkDecodeQuery observed %d valid samples (required 10); malformed matching rows: %d\n", file, query + 0, query_bad + 0
			failed = 1
		}
		if (json_bad || json < 10) {
			printf "bench-compare: %s: BenchmarkDecodeJSON observed %d valid samples (required 10); malformed matching rows: %d\n", file, json + 0, json_bad + 0
			failed = 1
		}
		exit failed
	}
	' "$file" >&2
}

compare_files() {
	local baseline=$1 candidate=$2
	validate_benchmark_file "$baseline"
	validate_benchmark_file "$candidate"
	echo "bench-compare: comparing recorded benchmark files"
	echo "bench-compare: baseline=$baseline"
	echo "bench-compare: candidate=$candidate"
	"$benchstat_bin" "$baseline" "$candidate"
}

if [[ "${1:-}" == "--files" ]]; then
	[[ $# -eq 3 ]] || { usage; exit 2; }
	compare_files "$2" "$3"
	exit $?
fi

if [[ $# -eq 2 && -f "$1" && -f "$2" ]]; then
	compare_files "$1" "$2"
	exit $?
fi

[[ $# -eq 2 ]] || { usage; exit 2; }
if [[ -e "$1" || -e "$2" ]]; then
	echo "bench-compare: both inputs must be Git refs, or use --files for benchmark files" >&2
	exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
go_bin=${GO:-go}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/kordn-bench-compare.XXXXXX")
baseline_tree="$tmp/baseline"
candidate_tree="$tmp/candidate"
baseline_out="$tmp/baseline.txt"
candidate_out="$tmp/candidate.txt"

cleanup() {
	set +e
	if [[ -d "$baseline_tree" ]]; then
		git -C "$root" worktree remove --force "$baseline_tree" >/dev/null 2>&1
	fi
	if [[ -d "$candidate_tree" ]]; then
		git -C "$root" worktree remove --force "$candidate_tree" >/dev/null 2>&1
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

add_worktree() {
	local ref=$1 tree=$2
	if ! git -C "$root" worktree add --detach -- "$tree" "$ref"; then
		echo "bench-compare: cannot create temporary worktree for Git ref: $ref" >&2
		return 1
	fi
}

run_sample() {
	local tree=$1 output=$2 label=$3
	local log="${output}.log"
	echo "bench-compare: preparing pinned iamlive catalog for $label"
	if ! (
		cd "$tree"
		./scripts/init-iamlive-submodule.sh
		./scripts/init-iamlive-submodule.sh --check
	); then
		echo "bench-compare: catalog preparation failed for $label; ensure repository-approved submodule access is available" >&2
		return 1
	fi
	echo "bench-compare: running 10 offline -benchmem samples for $label"
	if ! (
		cd "$tree"
		GOPROXY=off GOSUMDB=off "$go_bin" test ./internal/awsrequest -run '^$' \
			-bench='^(BenchmarkDecodeQuery|BenchmarkDecodeJSON)$' -benchmem -count=10 -benchtime=100ms
	) >"$output" 2>"$log"; then
		cat "$log" >&2
		cat "$output" >&2
		echo "bench-compare: benchmark command failed for $label" >&2
		return 1
	fi
	validate_benchmark_file "$output"
}

add_worktree "$1" "$baseline_tree"
add_worktree "$2" "$candidate_tree"
run_sample "$baseline_tree" "$baseline_out" baseline
run_sample "$candidate_tree" "$candidate_out" candidate

echo "bench-compare: common baseline/candidate decoder results (benchstat)"
echo "bench-compare: baseline ref=$1"
echo "bench-compare: candidate ref=$2"
"$benchstat_bin" "$baseline_out" "$candidate_out"
