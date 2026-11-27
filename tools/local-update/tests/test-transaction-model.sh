#!/bin/sh
# Synthetic transaction model regression suite; no production paths.
set -eu
umask 077
export LC_ALL=C
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
d=$(mktemp -d)
trap 'rm -rf -- "$d"' EXIT
cp "$here/transaction-model.sh" "$d/model.sh"
fresh() {
    r="$d/$1"; mkdir "$r"
    printf 'synthetic baseline\n' >"$r/active"
    printf 'synthetic candidate\n' >"$r/candidate"
    printf '1 %s\n' "$(sha256sum "$r/active" | cut -d' ' -f1)" >"$r/current"
}
invoke() { sh "$d/model.sh" "$r" "$@"; }
expect_exit() { expected=$1; shift; if invoke "$@"; then rc=0; else rc=$?; fi; test "$rc" = "$expected"; }
check() {
    test "$(cut -d' ' -f1 "$r/current")" = "$1"
    test "$(sha256sum "$r/active" | cut -d' ' -f1)" = "$(cut -d' ' -f2 "$r/current")"
    test ! -e "$r/txn" && test ! -e "$r/preparing" && test ! -e "$r/retired"
}
fresh success; invoke apply 2 none; check 2; echo PASS_SUCCESS
for point in before_journal after_journal after_swap after_health after_commit after_retire; do
    fresh "$point"; expect_exit 90 apply 2 "$point"
    invoke recover
    case "$point" in after_commit|after_retire) check 2;; *) check 1;; esac
    invoke recover
    invoke apply 3 none; check 3
    echo "PASS_INTERRUPTION $point"
done
fresh health_fail; expect_exit 78 apply 2 health_fail; check 1; echo PASS_HEALTH_ROLLBACK
fresh replay; invoke apply 2 none; expect_exit 78 apply 2 none; check 2; echo PASS_REPLAY
fresh bad_backup; expect_exit 90 apply 2 after_swap; printf 'damaged\n' >"$r/txn/old"; expect_exit 78 recover; test -d "$r/txn"; echo PASS_CORRUPT_BACKUP_HOLD
fresh bad_state; expect_exit 90 apply 2 after_swap; printf 'unknown\n' >"$r/current"; expect_exit 78 recover; test -d "$r/txn"; echo PASS_UNKNOWN_STATE_HOLD
fresh bad_committed; expect_exit 90 apply 2 after_commit; printf 'damaged\n' >"$r/active"; expect_exit 78 recover; test -d "$r/txn"; echo PASS_COMMITTED_PAYLOAD_MISMATCH_HOLD
echo TRANSACTION_MODEL_12_OF_12_PASS
