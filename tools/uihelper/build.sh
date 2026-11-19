#!/bin/sh
# Build the Sandroid UI helper (an app_process dex jar) from tools/uihelper/src.
#
#   tools/uihelper/build.sh
#
# Needs a JDK (javac, 11+) and an Android SDK with platforms/android-35 and any
# build-tools (for d8). Environment:
#   ANDROID_HOME  SDK root (default: ~/Library/Android/sdk)
#   BUILD_TOOLS   build-tools dir to use (default: the newest under the SDK)
#
# Writes src/sandroid/assets/uihelper/uihelper.jar and prints
#   JAR_SHA256=<hex>     paste into src/sandroid/core/uihelper.py
#   SOURCE_SHA256=<hex>  paste into src/sandroid/core/uihelper.py
# SOURCE_SHA256 is sha256 over, for every tools/uihelper/src/**/*.java sorted by
# its path relative to tools/uihelper/src: relpath, NUL, file bytes, NUL. It is
# defined identically by sandroid.core.uihelper.source_sha256().
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$HERE/src"
OUT="$ROOT/src/sandroid/assets/uihelper/uihelper.jar"

SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
if [ -z "${BUILD_TOOLS:-}" ]; then
    BUILD_TOOLS="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1 || true)"
fi
ANDROID_JAR="$SDK/platforms/android-35/android.jar"

die() {
    echo "build.sh: $*" >&2
    exit 1
}
command -v javac >/dev/null 2>&1 || die "javac not found (install a JDK 11+)"
[ -f "$ANDROID_JAR" ] || die "missing $ANDROID_JAR (sdkmanager \"platforms;android-35\")"
[ -n "$BUILD_TOOLS" ] && [ -x "$BUILD_TOOLS/d8" ] ||
    die "no d8 under $SDK/build-tools (sdkmanager \"build-tools;35.0.0\")"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    else
        shasum -a 256 | cut -d' ' -f1
    fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/uihelper-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir -p "$WORK/classes"

# Fixed, sorted source list so the build does not depend on directory order.
(cd "$SRC" && find . -name '*.java' | sed 's|^\./||' | LC_ALL=C sort) >"$WORK/sources.txt"
[ -s "$WORK/sources.txt" ] || die "no Java sources under $SRC"

# java.* from the JDK (--release 8), android.* from android.jar; d8 desugars.
(cd "$SRC" && javac --release 8 -encoding UTF-8 -nowarn -cp "$ANDROID_JAR" \
    -d "$WORK/classes" @"$WORK/sources.txt")
(cd "$WORK/classes" && find . -name '*.class' | LC_ALL=C sort) >"$WORK/classes.txt"
(cd "$WORK/classes" && "$BUILD_TOOLS/d8" --release --min-api 26 --lib "$ANDROID_JAR" \
    --output "$WORK/uihelper.jar" @"$WORK/classes.txt")

mkdir -p "$(dirname "$OUT")"
cp "$WORK/uihelper.jar" "$OUT"

SOURCE_SHA256="$(
    cd "$SRC"
    while IFS= read -r rel; do
        printf '%s\0' "$rel"
        cat "$rel"
        printf '\0'
    done <"$WORK/sources.txt" | sha256
)"
JAR_SHA256="$(sha256 <"$OUT")"

echo "javac: $(javac -version 2>&1)"
echo "d8: $BUILD_TOOLS"
echo "jar: $OUT ($(wc -c <"$OUT" | tr -d ' ') bytes)"
echo "JAR_SHA256=$JAR_SHA256"
echo "SOURCE_SHA256=$SOURCE_SHA256"
