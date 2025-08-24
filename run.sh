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
    exec cargo $@
fi

exec cargo run
