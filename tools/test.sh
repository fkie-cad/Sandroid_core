#!/usr/bin/env bash
# tools/test.sh -- the one way to run Sandroid's tests (agents, CI, humans).
#
#   tools/test.sh [quick]              parallel, skips slow/perf/quarantine tests
#   tools/test.sh full                 merge gate: parallel pass without perf and
#                                      quarantine tests, then a serial perf pass
#   tools/test.sh <path|nodeid>...     just these, serially (fast to start)
#   tools/test.sh --update-slow [JUNIT...]
#                                      rewrite tests/slow_tests.txt (the `slow`
#                                      tier) from the newest full run's parallel
#                                      pass: tests over SANDROID_TEST_SLOW_S
#                                      seconds (default 1.0); runs no tests
#
# Options (before or after the mode):
#   -n N        pytest-xdist workers (default 4 for quick/full, 1 for paths).
#               N is a request: the run takes what is free of the host-wide
#               worker budget (SANDROID_TEST_SLOTS, default 8) and never
#               fewer than 1. "auto" (one per CPU, no slot budget) is
#               accepted only when CI is set (CI runners are not shared).
#   -- ARGS     everything after -- goes to pytest unchanged
#
# Exit codes: 0 pass, 1 fail, 3 flaky (failed, then passed when the failed
# tests were rerun once, serially; logged to <cache>/flakes.jsonl).
#
# How it runs: a shared venv holds the dependencies only (keyed by pyproject
# deps + tools/test-constraints.txt + Python version, built with uv under a
# lock); this checkout's code comes from PYTHONPATH=<checkout>/src (plus a
# throwaway per-run overlay venv for child interpreters), never from an
# editable install, and tests/conftest.py refuses to run if `sandroid`
# resolves anywhere else. pytest runs under `env -i` with a throwaway HOME and
# TMPDIR, ANDROID_HOME pointing nowhere and stub adb/emulator/frida/... first
# on PATH. Bytecode is cached per checkout (PYTHONPYCACHEPREFIX), which cuts
# collection from ~45 s to ~10 s. JUnit XML and logs: .test-results/latest/.
# With CI set, bytecode goes to the usual __pycache__ dirs instead (the venv
# is fresh there and uv compiles it, UV_COMPILE_BYTECODE=1), and with
# GITHUB_STEP_SUMMARY set the summary is also appended to that file.
#
# Environment: SANDROID_TEST_CACHE (default ~/.cache/sandroid-tests),
# SANDROID_TEST_PYTHON (default python3.13), SANDROID_TEST_SLOTS (8),
# SANDROID_TEST_SLOT_WAIT (seconds to wait for the full -n before starting
# with fewer, default 20), SANDROID_TEST_SLOW_S (--update-slow threshold).
# SANDROID_TESTS_STRICT_DEVICE and SANDROID_TESTS_BLOCKED_LOG are passed on
# to tests/conftest.py's device guard.
#
# Plain bash 3.2 (macOS) compatible; no flock needed.

set -o pipefail

WT=$(cd "$(dirname "$0")/.." && pwd -P)
CACHE=${SANDROID_TEST_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/sandroid-tests}
MAX_SLOTS=${SANDROID_TEST_SLOTS:-8}
SLOT_WAIT=${SANDROID_TEST_SLOT_WAIT:-20}
CONSTRAINTS="$WT/tools/test-constraints.txt"

die() { echo "tools/test.sh: $*" >&2; exit 1; }
say() { echo "== $*" >&2; }

# ---------------------------------------------------------------- arguments
MODE=""
NREQ=""
TARGETS=()
PASS=()
while [ $# -gt 0 ]; do
    case $1 in
        -n) [ $# -ge 2 ] || die "-n needs a number"; NREQ=$2; shift 2 ;;
        -n*) NREQ=${1#-n}; shift ;;
        --) shift; PASS=("$@"); break ;;
        -h|--help) sed -n '2,/^# Plain bash/p' "$0"; exit 0 ;;
        quick|full|--update-slow)
            [ -z "$MODE" ] || die "give one mode"
            MODE=${1#--}; shift ;;
        -*) die "unknown option $1 (pytest options go after --)" ;;
        *) TARGETS+=("$1"); shift ;;
    esac
done
if [ ${#TARGETS[@]} -gt 0 ] && [ "$MODE" != update-slow ]; then
    [ -z "$MODE" ] || die "give either a mode or paths, not both"
    MODE=paths
fi
MODE=${MODE:-quick}
# CI runners are not shared: no host-wide slot budget there.
IN_CI=""
[ -n "${CI:-}" ] && [ "${CI:-}" != false ] && IN_CI=1
case $NREQ in
    "") if [ "$MODE" = paths ]; then NREQ=1; else NREQ=4; fi ;;
    auto)
        [ -n "$IN_CI" ] || die "-n auto only with CI set (this host's workers are shared; give a number)"
        NREQ=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2) ;;
    *[!0-9]*|0) die "-n takes a positive number (or 'auto' with CI set)" ;;
esac

# ------------------------------------------------------------------ helpers
hash16() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi |
        cut -c1-16
}

pid_alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }

# mkdir is atomic everywhere; a lock dir holds the owner's pid.
lock_take() {  # $1 = lock dir; returns 0 if taken
    if mkdir "$1" 2>/dev/null; then
        echo $$ >"$1/pid"
        return 0
    fi
    return 1
}

lock_reap() {  # $1 = lock dir; removes it if its owner is gone
    local pid
    [ -d "$1" ] || return 0
    pid=$(cat "$1/pid" 2>/dev/null)
    if [ -z "$pid" ]; then
        # Between mkdir and writing the pid; only stale if it stays empty.
        if [ -n "$(find "$1" -maxdepth 0 -mmin +1 2>/dev/null)" ]; then
            rm -rf "$1"
        fi
        return 0
    fi
    pid_alive "$pid" || rm -rf "$1"
}

# ------------------------------------------------------------- shared venv
find_python() {
    local p
    for p in "${SANDROID_TEST_PYTHON:-}" /opt/homebrew/bin/python3.13 python3.13; do
        [ -n "$p" ] || continue
        p=$(command -v "$p" 2>/dev/null) || continue
        echo "$p"
        return 0
    done
    return 1
}

PY=$(find_python) || die "Python 3.13 not found (set SANDROID_TEST_PYTHON)"

# ------------------------------------------------------ --update-slow mode
if [ "$MODE" = update-slow ]; then
    if [ ${#TARGETS[@]} -eq 0 ]; then
        # Newest full run's parallel pass (run dirs sort by start time).
        SRC=$(ls -1d "$WT"/.test-results/2*-*/junit-parallel.xml 2>/dev/null | sort | tail -n 1)
        [ -n "$SRC" ] || die "no full run in $WT/.test-results; run tools/test.sh full first"
        TARGETS=("$SRC")
    fi
    "$PY" -I - "$WT/tests/slow_tests.txt" "${SANDROID_TEST_SLOW_S:-1.0}" \
        "${TARGETS[@]}" <<'EOF'
import os, sys, xml.etree.ElementTree as ET

out, threshold, files = sys.argv[1], float(sys.argv[2]), sys.argv[3:]

def nodeid(tc):  # as in summarize() below
    f, cls, name = tc.get("file") or "", tc.get("classname") or "", tc.get("name")
    mod = f[:-3].replace("/", ".") if f.endswith(".py") else ""
    rest = cls[len(mod) + 1:] if mod and cls.startswith(mod + ".") else ""
    parts = [f or cls] + (rest.split(".") if rest else []) + [name]
    return "::".join(p for p in parts if p)

slow, total = {}, 0
for path in files:
    for tc in ET.parse(path).getroot().iter("testcase"):
        total += 1
        t = float(tc.get("time") or 0)
        if t > threshold and "::" in nodeid(tc):
            slow[nodeid(tc)] = max(t, slow.get(nodeid(tc), 0.0))
if not total:
    sys.exit(f"tools/test.sh: no test cases in {', '.join(files)}")
srcs = ", ".join(os.path.relpath(p, os.path.dirname(os.path.dirname(out))) for p in files)
with open(out, "w", encoding="utf-8") as fh:
    fh.write(
        "# The `slow` tier: tests over %.1f s in the parallel pass of a\n"
        "# `tools/test.sh full` run. `tools/test.sh quick` skips them; tests/conftest.py\n"
        "# marks them. Regenerate with `tools/test.sh --update-slow` after a full run\n"
        "# (do not edit by hand). Source: %s\n" % (threshold, srcs)
    )
    fh.writelines(f"{n}\n" for n in sorted(slow))
print(f"   {len(slow)} of {total} tests over {threshold:g} s -> {out}")
EOF
    exit $?
fi

command -v uv >/dev/null 2>&1 || die "uv not found (https://docs.astral.sh/uv/)"
[ -f "$CONSTRAINTS" ] || die "missing $CONSTRAINTS"

PYVER=$("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
KEY=$( {
    # [project] dependencies and every optional-dependency group.
    sed -n '/^dependencies = \[/,/^\[project.scripts\]/p' "$WT/pyproject.toml"
    cat "$CONSTRAINTS"
    echo "python $PYVER"
} | hash16)
VENV="$CACHE/venvs/$KEY"
mkdir -p "$CACHE/venvs" "$CACHE/slots" "$CACHE/pyc" || die "cannot create $CACHE"

build_venv() {
    local tmp="$VENV.tmp.$$" req
    say "building test venv $KEY (Python $PYVER, deps only) ..."
    rm -rf "$tmp"
    # Only the dependency lists: installing pyproject.toml itself would make
    # Sandroid importable from the venv (and `full` names Sandroid[...]).
    req="$tmp.requirements.txt"
    "$PY" - "$WT/pyproject.toml" >"$req" <<'EOF' || return 1
import sys, tomllib
proj = tomllib.load(open(sys.argv[1], "rb"))["project"]
extras = proj.get("optional-dependencies", {})
deps = list(proj["dependencies"])
for group in ("dev", "static-analysis"):
    deps += extras.get(group, [])
print("\n".join(d for d in deps if not d.lower().startswith("sandroid")))
EOF
    uv venv -q -p "$PY" "$tmp" &&
        uv pip install -q -p "$tmp/bin/python" -r "$req" -c "$CONSTRAINTS" &&
        rm -f "$req" &&
        touch "$tmp/.complete" &&
        rm -rf "$VENV" && mv "$tmp" "$VENV"
}

ensure_venv() {
    local lock="$VENV.lock" waited=0
    [ -f "$VENV/.complete" ] && return 0
    while ! lock_take "$lock"; do
        lock_reap "$lock"
        [ -f "$VENV/.complete" ] && return 0
        [ $waited -eq 0 ] && say "waiting for another run to finish building the venv ..."
        waited=$((waited + 1))
        sleep 2
    done
    if [ ! -f "$VENV/.complete" ]; then
        if ! build_venv; then
            rm -rf "$VENV.tmp.$$" "$VENV.tmp.$$.requirements.txt" "$lock"
            die "venv build failed"
        fi
    fi
    rm -rf "$lock"
}

# ------------------------------------------------- host-wide worker budget
HELD=""
NHELD=0

release_slots() {
    local i
    for i in $HELD; do
        [ "$(cat "$CACHE/slots/$i/pid" 2>/dev/null)" = "$$" ] && rm -rf "$CACHE/slots/$i"
    done
    HELD=""
    NHELD=0
}

acquire_slots() {  # $1 = wanted; takes up to that many, at least one
    local want=$1 start=$SECONDS told=0 i
    if [ -n "$IN_CI" ]; then  # not shared: take what was asked for
        NHELD=$want
        return 0
    fi
    [ "$want" -le "$MAX_SLOTS" ] || want=$MAX_SLOTS
    while :; do
        i=1
        while [ $i -le "$MAX_SLOTS" ] && [ $NHELD -lt "$want" ]; do
            lock_reap "$CACHE/slots/$i"
            if lock_take "$CACHE/slots/$i"; then
                HELD="$HELD $i"
                NHELD=$((NHELD + 1))
            fi
            i=$((i + 1))
        done
        [ $NHELD -ge "$want" ] && return 0
        [ $NHELD -ge 1 ] && [ $((SECONDS - start)) -ge "$SLOT_WAIT" ] && return 0
        if [ $told -eq 0 ]; then
            say "host worker budget busy ($MAX_SLOTS slots in $CACHE/slots); have $NHELD of $want, waiting ..."
            told=1
        fi
        sleep 1
    done
}

# ------------------------------------------------------------- run layout
RUN=""
cleanup() {
    release_slots
    [ -n "$RUN" ] && rm -rf "$RUN"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ensure_venv
"$VENV/bin/python" -c 'import xdist' 2>/dev/null ||
    die "venv $VENV lacks pytest-xdist; delete it and rerun"

# Short base path: AF_UNIX socket paths below tmp_path must stay < 104 bytes.
RUN=$(mktemp -d "/tmp/sdt.XXXXXX") || die "mktemp failed"
mkdir -p "$RUN/home" "$RUN/tmp" "$RUN/cwd" "$RUN/stubs"

# A per-run overlay venv (~30 ms): its site-packages adds this checkout's src/
# and then the shared venv's site-packages. PYTHONPATH alone is not enough:
# tests start `sys.executable -m sandroid...` children with a scrubbed
# environment (e.g. the MCP stdio client), and those must import this tree too.
uv venv -q -p "$PY" "$RUN/py" || die "overlay venv failed"
SHARED_SITE=$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
OVERLAY_SITE=$("$RUN/py/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
{
    echo "$WT/src"
    echo "import site; site.addsitedir('$SHARED_SITE')"
} >"$OVERLAY_SITE/_sandroid_checkout.pth"

# Stub device/host tools: anything that slips past tests/conftest.py's
# guard finds a "broken adb" (exit 1) instead of a real one. Logged.
for tool in adb emulator emulator-headless avdmanager sdkmanager frida frida-ps \
    frida-server objection fritap mitmdump mitmweb mitmproxy pkill killall; do
    cat >"$RUN/stubs/$tool" <<'EOF'
#!/bin/sh
echo "[${PYTEST_CURRENT_TEST:-}] ${0##*/} $*" >>"${SDROID_STUB_LOG:-/dev/null}"
exit 1
EOF
    chmod +x "$RUN/stubs/$tool"
done

RESULTS_ROOT="$WT/.test-results"
OUT="$RESULTS_ROOT/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$OUT" || die "cannot create $OUT"
ln -sfn "$(basename "$OUT")" "$RESULTS_ROOT/latest"
# Keep the last 10 runs.
ls -1d "$RESULTS_ROOT"/2*-* 2>/dev/null | sort | sed -e :a -e '$d;N;2,10ba' -e 'P;D' |
    while read -r old; do rm -rf "$old"; done

PYC="$CACHE/pyc/$(printf '%s' "$WT" | hash16)"
case $(uname -s) in Darwin) LOCALE=en_US.UTF-8 ;; *) LOCALE=C.UTF-8 ;; esac
EXTRA_ENV=()
# In CI the prefix would start empty and hide the bytecode uv compiled into
# the fresh venv; there the checkout's __pycache__ dirs are fine.
[ -n "$IN_CI" ] || EXTRA_ENV+=(PYTHONPYCACHEPREFIX="$PYC")
for var in SANDROID_TESTS_STRICT_DEVICE SANDROID_TESTS_BLOCKED_LOG; do
    eval "val=\${$var:-}"
    [ -z "$val" ] || EXTRA_ENV+=("$var=$val")
done

pytest_run() {  # $1 = log name; rest = pytest args. Tees the output; returns rc.
    local name=$1
    shift
    (
        cd "$RUN/cwd" &&
            env -i \
                HOME="$RUN/home" TMPDIR="$RUN/tmp" \
                PATH="$RUN/stubs:$RUN/py/bin:$VENV/bin:/usr/bin:/bin" \
                TERM=xterm-256color LANG=$LOCALE LC_ALL=$LOCALE PYTHONUTF8=1 \
                ANDROID_HOME=/nonexistent ANDROID_SDK_ROOT=/nonexistent \
                PYTHONPATH="$WT/src" SDROID_STUB_LOG="$OUT/stub-calls.log" \
                ${EXTRA_ENV[@]+"${EXTRA_ENV[@]}"} \
                "$RUN/py/bin/python" -m pytest -c "$WT/pyproject.toml" --rootdir "$WT" \
                -p no:cacheprovider -o junit_family=xunit1 \
                --junitxml="$OUT/junit-$name.xml" "$@"
    ) 2>&1 | tee "$OUT/$name.log"
}

summarize() {  # args: junit files; writes $OUT/failed.txt (node ids)
    "$VENV/bin/python" -I - "$OUT/failed.txt" "$@" <<'EOF'
import os, sys, xml.etree.ElementTree as ET

failed_out, files = sys.argv[1], sys.argv[2:]

def nodeid(tc):
    f, cls, name = tc.get("file") or "", tc.get("classname") or "", tc.get("name")
    mod = f[:-3].replace("/", ".") if f.endswith(".py") else ""
    rest = cls[len(mod) + 1:] if mod and cls.startswith(mod + ".") else ""
    parts = [f or cls] + (rest.split(".") if rest else []) + [name]
    return "::".join(p for p in parts if p)

tot = dict(tests=0, failed=0, errors=0, skipped=0, time=0.0)
failed = []
for path in files:
    if not os.path.exists(path):
        continue
    root = ET.parse(path).getroot()
    for s in root.iter("testsuite"):
        tot["tests"] += int(s.get("tests", 0))
        tot["failed"] += int(s.get("failures", 0))
        tot["errors"] += int(s.get("errors", 0))
        tot["skipped"] += int(s.get("skipped", 0))
        tot["time"] += float(s.get("time", 0))
    for tc in root.iter("testcase"):
        for c in tc:
            if c.tag in ("failure", "error"):
                msg = (c.get("message") or "").strip().splitlines()
                failed.append((nodeid(tc), c.tag, msg[0][:160] if msg else ""))
passed = tot["tests"] - tot["failed"] - tot["errors"] - tot["skipped"]
print(f"   {tot['tests']} tests: {passed} passed, {tot['failed']} failed, "
      f"{tot['errors']} errors, {tot['skipped']} skipped "
      f"(pytest time {tot['time']:.0f} s)")
for nid, kind, msg in failed:
    print(f"   {kind.upper():7} {nid}\n           {msg}")
with open(failed_out, "w") as fh:
    # A collection error has no test node id to rerun.
    fh.write("".join(f"{n}\n" for n, _, _ in failed if "::" in n))
sys.exit(0 if not failed or all("::" in n for n, _, _ in failed) else 2)
EOF
}

log_flakes() {  # $1 = file with flaky node ids
    local branch commit
    branch=$(git -C "$WT" rev-parse --abbrev-ref HEAD 2>/dev/null)
    commit=$(git -C "$WT" rev-parse --short HEAD 2>/dev/null)
    "$VENV/bin/python" -I - "$1" "$CACHE/flakes.jsonl" "$WT" "$branch" "$commit" \
        "$MODE" "$N" <<'EOF'
import json, sys, time
ids, log, wt, branch, commit, mode, workers = sys.argv[1:]
with open(log, "a") as fh:
    for nid in filter(None, open(ids).read().split("\n")):
        fh.write(json.dumps(dict(
            ts=time.strftime("%Y-%m-%dT%H:%M:%S%z"), nodeid=nid, worktree=wt,
            branch=branch, commit=commit, mode=mode, workers=int(workers),
        )) + "\n")
EOF
}

# --------------------------------------------------------------------- run
START=$SECONDS
acquire_slots "$NREQ"
N=$NHELD
XDIST=()
[ "$N" -gt 1 ] && XDIST=(-n "$N" --dist worksteal)
say "$MODE: $WT (Python $PYVER, $N worker(s), venv $KEY)"

RC=0
JUNITS=()
case $MODE in
    quick)
        pytest_run quick ${XDIST[@]+"${XDIST[@]}"} \
            -m "not slow and not quarantine and not perf" \
            ${PASS[@]+"${PASS[@]}"} "$WT/tests"
        RC=$?
        JUNITS=("$OUT/junit-quick.xml")
        ;;
    full)
        pytest_run parallel ${XDIST[@]+"${XDIST[@]}"} \
            -m "not quarantine and not perf" ${PASS[@]+"${PASS[@]}"} "$WT/tests"
        RC=$?
        JUNITS=("$OUT/junit-parallel.xml")
        if [ $RC -le 1 ]; then
            say "perf pass (serial)"
            pytest_run perf -m "perf and not quarantine" ${PASS[@]+"${PASS[@]}"} "$WT/tests"
            PRC=$?
            [ $PRC -eq 5 ] && PRC=0  # no perf tests selected
            [ $PRC -gt $RC ] && RC=$PRC
            JUNITS+=("$OUT/junit-perf.xml")
        fi
        ;;
    paths)
        ABS=()
        for t in "${TARGETS[@]}"; do
            case $t in /*) ABS+=("$t") ;; *) ABS+=("$PWD/$t") ;; esac
        done
        pytest_run paths ${XDIST[@]+"${XDIST[@]}"} ${PASS[@]+"${PASS[@]}"} "${ABS[@]}"
        RC=$?
        JUNITS=("$OUT/junit-paths.xml")
        ;;
esac

echo
say "summary ($MODE, $N worker(s), $((SECONDS - START)) s wall)"
summarize "${JUNITS[@]}" | tee "$OUT/summary.txt"
SUMRC=$?
FINAL=$RC
if [ $RC -eq 1 ] && [ $SUMRC -eq 0 ] && [ -s "$OUT/failed.txt" ]; then
    NFAILED=$(wc -l <"$OUT/failed.txt" | tr -d ' ')
    if [ "$NFAILED" -gt 20 ]; then
        say "$NFAILED failures: not rerunning (that is not flakiness)"
    else
        release_slots
        acquire_slots 1
        say "rerunning the $NFAILED failed test(s) once, serially"
        RERUN=()
        while read -r nid; do RERUN+=("$WT/$nid"); done <"$OUT/failed.txt"
        cp "$OUT/failed.txt" "$OUT/failed-first.txt"
        pytest_run rerun -p no:randomly ${PASS[@]+"${PASS[@]}"} "${RERUN[@]}" >/dev/null
        RRC=$?
        summarize "$OUT/junit-rerun.xml" >/dev/null
        if [ $RRC -eq 0 ]; then
            FINAL=3
            log_flakes "$OUT/failed-first.txt"
            echo
            echo "!! FLAKY: these failed in the run and passed when rerun alone:"
            sed 's/^/!!   /' "$OUT/failed-first.txt"
            echo "!! (logged to $CACHE/flakes.jsonl; exit 3 -- report them; a merge"
            echo "!!  is OK only if they are unrelated to the change)"
        else
            echo
            echo "!! still failing when rerun alone (see $OUT/rerun.log):"
            sed 's/^/!!   /' "$OUT/failed.txt"
            FINAL=1
        fi
    fi
elif [ $RC -ne 0 ] && [ $RC -ne 1 ]; then
    say "pytest exited with $RC (interrupted, internal or usage error, or nothing collected)"
    FINAL=1
fi
if [ -s "$OUT/stub-calls.log" ]; then
    say "$(wc -l <"$OUT/stub-calls.log" | tr -d ' ') call(s) reached the stub adb/emulator/frida (see $OUT/stub-calls.log)"
fi
say "results: $OUT  ->  exit $FINAL"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        case $FINAL in 0) verdict=passed ;; 3) verdict="flaky (exit 3)" ;; *) verdict="FAILED (exit $FINAL)" ;; esac
        echo "### tools/test.sh $MODE: $verdict"
        echo
        echo "Python $PYVER, $N worker(s), $((SECONDS - START)) s wall"
        echo
        echo '```'
        cat "$OUT/summary.txt" 2>/dev/null
        if [ "$FINAL" -eq 3 ]; then
            echo
            echo "flaky (failed in the run, passed when rerun alone):"
            sed 's/^/  /' "$OUT/failed-first.txt"
        elif [ -f "$OUT/failed-first.txt" ]; then
            echo
            echo "still failing when rerun alone:"
            sed 's/^/  /' "$OUT/failed.txt"
        fi
        echo '```'
    } >>"$GITHUB_STEP_SUMMARY"
fi
exit $FINAL
