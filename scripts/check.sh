#!/usr/bin/env sh
#
# The repository quality gate. Reports, never rewrites.
#
#   sh scripts/check.sh
#
# Runs rustfmt, clippy and the tests with every feature on, then filet. The database tests run
# when TEST_DATABASE_URL is set and announce a skip otherwise (see docs/development.md). When
# it is set, the gate waits for the server with pg_isready first: a test that connects while
# Postgres is still starting fails with UnexpectedEof instead of skipping. It first refuses a
# local dependency (`path =` or a `file://` git source): a tag built that way only builds here.

set -eu

cd "$(git rev-parse --show-toplevel)"

if grep -nE '(^|[{,[:space:]])path[[:space:]]*=|file://' Cargo.toml Cargo.lock; then
  echo "check: a local dependency only builds on this machine; depend on a git tag" >&2
  exit 1
fi

if [ -n "${TEST_DATABASE_URL:-}" ] && command -v pg_isready >/dev/null 2>&1; then
  tries=0
  until pg_isready -d "$TEST_DATABASE_URL" -q; do
    tries=$((tries + 1))
    if [ "$tries" -ge 30 ]; then
      echo "check: Postgres at TEST_DATABASE_URL is not ready after 30 s" >&2
      exit 1
    fi
    sleep 1
  done
fi

cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
if command -v filet >/dev/null 2>&1; then
  filet check .
else
  echo "check: no 'filet' on PATH, skipping the filet pass (CI still runs it)" >&2
fi
