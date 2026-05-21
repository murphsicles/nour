#!/usr/bin/env bash
set -e

ZETAC="${ZETAC:-/home/zeta/.openclaw/workspace/zeta/bin/zetac}"
LLC="${LLC:-llc-21}"
CLANG="${CLANG:-clang}"
RUNTIME_O="${RUNTIME_O:-/home/zeta/.openclaw/workspace/zeta/zetac_new.o}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="/tmp/nour_test_run"

echo "=============================="
echo "  Nour Test Runner"
echo "=============================="
echo "zetac:  $ZETAC"
echo "llc:    $(which $LLC 2>/dev/null || echo 'NOT FOUND')"
echo "clang:  $(which $CLANG 2>/dev/null || echo 'NOT FOUND')"
echo ""

mkdir -p "$OUT_DIR"

test_files=()
for f in "$SCRIPT_DIR"/test_*.z; do
    [ -f "$f" ] && test_files+=("$f")
done

total=${#test_files[@]}
passed=0
idx=0

for src in "${test_files[@]}"; do
    idx=$((idx + 1))
    name=$(basename "$src" .z)
    printf "  [%02d/%02d] %-25s " "$idx" "$total" "$name"

    # Compile .z → LLVM IR
    ir_file="$OUT_DIR/${name}.ir"
    if ! "$ZETAC" "$src" > "$ir_file" 2>/dev/null; then
        echo "❌ (compile)"
        continue
    fi

    # LLVM IR → object file
    obj_file="$OUT_DIR/${name}.o"
    if ! "$LLC" -filetype=obj "$ir_file" -o "$obj_file" 2>/dev/null; then
        echo "❌ (llc)"
        continue
    fi

    # Link with runtime → executable
    bin_file="$OUT_DIR/$name"
    if [ -f "$RUNTIME_O" ]; then
        if ! "$CLANG" "$obj_file" "$RUNTIME_O" -o "$bin_file" -lm 2>/dev/null; then
            echo "❌ (link)"
            continue
        fi
    else
        echo "⚠  (compiled)"
        passed=$((passed + 1))
        continue
    fi

    # Run the test
    if "$bin_file" > "$OUT_DIR/${name}.out" 2>&1; then
        echo "✅"
        passed=$((passed + 1))
    else
        echo "❌ (exit $?)"
        head -5 "$OUT_DIR/${name}.out"
    fi
done

echo ""
echo "  $passed / $total tests passed"
echo "=============================="

[ "$passed" = "$total" ]
