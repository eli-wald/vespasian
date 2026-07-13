#!/usr/bin/env bash
# Tests for run-live-tests.sh --group flag and target resolution.
# Does NOT run actual live tests — only validates argument parsing
# and target-list construction.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1" >&2; }

# ── Source the target arrays and helper from the runner ──────────
# We extract just the pieces we need without running main().

source <(sed -n '/^OFFLINE_TARGETS=(/,/^)/p' "$SCRIPT_DIR/run-live-tests.sh")
source <(sed -n '/^LIVE_TARGETS=(/,/^)/p' "$SCRIPT_DIR/run-live-tests.sh")
source <(grep '^join_targets()' "$SCRIPT_DIR/run-live-tests.sh")

echo "=== Target group resolution ==="

# Test 1: --group offline produces exactly OFFLINE_TARGETS
offline="$(join_targets "${OFFLINE_TARGETS[@]}")"
offline_count=$(echo "$offline" | tr ',' '\n' | wc -l | tr -d ' ')
if [[ "$offline_count" -eq 19 ]]; then
    pass "--group offline: 19 targets"
else
    fail "--group offline: expected 19 targets, got $offline_count"
fi

# Test 2: --group live produces exactly LIVE_TARGETS
live="$(join_targets "${LIVE_TARGETS[@]}")"
live_count=$(echo "$live" | tr ',' '\n' | wc -l | tr -d ' ')
if [[ "$live_count" -eq 6 ]]; then
    pass "--group live: 6 targets"
else
    fail "--group live: expected 6 targets, got $live_count"
fi

# Test 3: --group all (no TARGETS_SETUP) includes all 25 targets
all="${live},${offline}"
all_count=$(echo "$all" | tr ',' '\n' | wc -l | tr -d ' ')
if [[ "$all_count" -eq 25 ]]; then
    pass "--group all (no config): 25 targets"
else
    fail "--group all (no config): expected 25 targets, got $all_count"
fi

# Test 4: edge-cases and crawl-depth are always present in all mode
if echo "$all" | grep -q 'edge-cases' && echo "$all" | grep -q 'crawl-depth'; then
    pass "--group all includes edge-cases and crawl-depth"
else
    fail "--group all missing edge-cases or crawl-depth"
fi

# Test 5: --group all with TARGETS_SETUP deduplicates correctly
TARGETS_SETUP="rest-api,soap-service,graphql-server,grpc-server,concat-spa"
merged="${TARGETS_SETUP},${all}"
deduped=$(echo "$merged" | tr ',' '\n' | awk '!s[$0]++' | paste -sd, -)
deduped_count=$(echo "$deduped" | tr ',' '\n' | wc -l | tr -d ' ')
if [[ "$deduped_count" -eq 26 ]]; then
    pass "--group all with TARGETS_SETUP: 26 targets (25 + grpc-server)"
else
    fail "--group all with TARGETS_SETUP: expected 26 targets, got $deduped_count"
fi

# Test 6: grpc-server is present after TARGETS_SETUP merge
if echo "$deduped" | grep -q 'grpc-server'; then
    pass "TARGETS_SETUP adds grpc-server"
else
    fail "TARGETS_SETUP did not add grpc-server"
fi

# Test 7: no duplicates after dedup
dup_count=$(echo "$deduped" | tr ',' '\n' | sort | uniq -d | wc -l | tr -d ' ')
if [[ "$dup_count" -eq 0 ]]; then
    pass "No duplicates after dedup"
else
    fail "Found $dup_count duplicates after dedup"
fi

echo ""
echo "=== join_targets helper ==="

# Test 8: join_targets produces comma-separated output
arr=(a b c)
result="$(join_targets "${arr[@]}")"
if [[ "$result" == "a,b,c" ]]; then
    pass "join_targets: 'a,b,c'"
else
    fail "join_targets: expected 'a,b,c', got '$result'"
fi

# Test 9: join_targets with single element
result="$(join_targets "only")"
if [[ "$result" == "only" ]]; then
    pass "join_targets single: 'only'"
else
    fail "join_targets single: expected 'only', got '$result'"
fi

echo ""
echo "=== Argument validation ==="

# Test 10: invalid --group value exits non-zero
# We can't easily source main() without side effects, so invoke the script
# with a dummy config to test the error path.
tmpconfig=$(mktemp)
echo "TARGETS_SETUP=" > "$tmpconfig"
if env CONFIG_FILE="$tmpconfig" bash -c "
    source '$SCRIPT_DIR/run-live-tests.sh' --group bogus 2>/dev/null
" 2>/dev/null; then
    fail "Invalid --group should exit non-zero"
else
    pass "Invalid --group exits non-zero"
fi
rm -f "$tmpconfig"

echo ""
echo "=== Summary ==="
echo "  $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
