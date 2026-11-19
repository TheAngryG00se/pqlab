#!/usr/bin/env bash
set -euo pipefail
tool=$1
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export PQLAB_HOME="$work/store"
umask 077
cd "$work"

expect_failure() {
  if "$@" >stdout 2>stderr; then
    echo "Expected command failure" >&2
    exit 1
  fi
}

"$tool" --help >help
test -s help
"$tool" list >keys
test ! -s keys
head -c 32 /dev/urandom >password
password_args=(--password-file password)
printf 'bad envelope' >broken
expect_failure "$tool" decrypt broken opened "${password_args[@]}"
test ! -e opened
expect_failure "$tool" create ML-KEM-512 sample
expect_failure "$tool" encrypt ML-KEM-512 AES-256 broken encrypted
test ! -e encrypted
if [[ ${2:-} != full ]]; then exit 0; fi

head -c 65537 /dev/urandom >source
old_id=$("$tool" create ML-KEM-512 sample "${password_args[@]}")
test "${#old_id}" -eq 32
"$tool" encrypt ML-KEM-512 AES-256 source encrypted
test "$(stat -c %a encrypted)" = 600
printf sentinel >existing
expect_failure "$tool" encrypt ML-KEM-512 AES-256 source existing
test "$(cat existing)" = sentinel

new_id=$("$tool" rotate "$old_id" "${password_args[@]}")
test "$old_id" != "$new_id"
"$tool" list >keys
grep -Fq "$old_id"$'\tML-KEM-512\tretired\t' keys
grep -Fq "$new_id"$'\tML-KEM-512\tactive\t' keys
"$tool" rewrap encrypted migrated "${password_args[@]}"
test "$(stat -c %a migrated)" = 600
"$tool" decrypt migrated opened "${password_args[@]}"
test "$(stat -c %a opened)" = 600
cmp source opened
cp migrated corrupt
truncate -s -1 corrupt
expect_failure "$tool" decrypt corrupt rejected "${password_args[@]}"
test ! -e rejected
