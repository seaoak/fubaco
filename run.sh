#!/bin/bash

set -x
set -e

test -f fubaco.log && mv fubaco.log fubaco.log.bak
test -f dns_cache.json && cp -p dns_cache.json dns_cache.json.bak

test -f .env && source .env

export RUST_BACKTRACE=1
#export RUST_BACKTRACE=full

rustup -V
rustup show -v

if test "X$1" == "Xtest"; then
    time cargo "$@"
    exit $?
fi

if test "X$1" == "Xsamply"; then
    # https://hazm.at/mox/lang/rust/recipes/devenv/profiler/index.html
    which samply > /dev/null || exit 2
    shift
    exec samply "$@"
fi

if test "X$1" == "X--release"; then
    time cargo run "$@"
    exit $?
fi

if test $# -ge 1; then
    time cargo "$@"
    exit $?
fi

time cargo run
