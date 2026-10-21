# shellcheck shell=bash
# Shared bats setup: load dist/mili.sh WITHOUT losing bats' own `run`.
# mili defines `run()` (its dry-run command wrapper); sourcing it would shadow
# bats' `run`, leaving $status/$output unset in every test. So: save bats' run,
# source mili, then put bats' run back. mili code that calls `run` internally is
# not exercised by these pure-function tests (system writers are stubbed).
mili_load() {
  export MILI_ETC="$BATS_TEST_TMPDIR/etc"
  export MILI_LOGDIR="$BATS_TEST_TMPDIR/log"
  export MILI_COLOR=never MILI_PUBIP4=1.1.1.1
  mkdir -p "$MILI_ETC" "$MILI_LOGDIR"
  eval "_bats_run_saved() $(declare -f run | tail -n +2)"
  set -- version
  # shellcheck disable=SC1090
  source "$BATS_TEST_DIRNAME/../../dist/mili.sh" >/dev/null 2>&1
  eval "run() $(declare -f _bats_run_saved | tail -n +2)"
  # never touch the real host from unit tests
  sysctl_set_reserved_ports() { :; }
}

# negative assert that really fails the test (bats/set -e ignores a bare `! cmd`)
refute() { if "$@"; then echo "unexpectedly succeeded: $*"; return 1; fi; return 0; }
