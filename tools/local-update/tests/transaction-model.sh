#!/bin/sh
set -eu
export LC_ALL=C
root=$1
action=$2
hash() { sha256sum "$1" | cut -d' ' -f1; }
record() { printf '%s %s\n' "$1" "$(hash "$2")"; }
match() { test -f "$1" && test -f "$2" && test "$(cut -d' ' -f2 "$2")" = "$(hash "$1")"; }
replace() { cp "$1" "$2.next"; mv -f "$2.next" "$2"; }
finish() { mv "$root/txn" "$root/retired"; rm -rf "$root/retired"; }
recover() {
    if test ! -d "$root/txn"; then
        match "$root/active" "$root/current" || return 78
        rm -rf "$root/preparing" "$root/retired"
        return 0
    fi
    t=$root/txn
    test ! -e "$root/retired" && test ! -e "$root/preparing" || return 78
    match "$t/old" "$t/old.state" || return 78
    match "$t/new" "$t/new.state" || return 78
    if cmp -s "$root/current" "$t/new.state"; then
        match "$root/active" "$t/new.state" || return 78
    elif cmp -s "$root/current" "$t/old.state"; then
        replace "$t/old" "$root/active"
        match "$root/active" "$root/current" || return 78
    else
        return 78
    fi
    finish
}
case "$action" in
recover) recover ;;
apply)
    seq=$3; stop=$4
    test ! -e "$root/txn" && test ! -e "$root/retired" && test ! -e "$root/preparing" || exit 78
    match "$root/active" "$root/current" || exit 78
    floor=$(cut -d' ' -f1 "$root/current")
    case "$seq" in ''|*[!0-9]*) exit 78;; esac
    test "$seq" -gt "$floor" || exit 78
    mkdir "$root/preparing"
    cp "$root/active" "$root/preparing/old"
    cp "$root/current" "$root/preparing/old.state"
    cp "$root/candidate" "$root/preparing/new"
    record "$seq" "$root/preparing/new" >"$root/preparing/new.state"
    test "$stop" != before_journal || exit 90
    mv "$root/preparing" "$root/txn"
    test "$stop" != after_journal || exit 90
    replace "$root/txn/new" "$root/active"
    test "$stop" != after_swap || exit 90
    if test "$stop" = health_fail; then recover; exit 78; fi
    match "$root/active" "$root/txn/new.state" || exit 78
    test "$stop" != after_health || exit 90
    replace "$root/txn/new.state" "$root/current"
    test "$stop" != after_commit || exit 90
    mv "$root/txn" "$root/retired"
    test "$stop" != after_retire || exit 90
    rm -rf "$root/retired"
    ;;
*) exit 78 ;;
esac
