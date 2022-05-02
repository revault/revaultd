#!/usr/bin/env sh

# From the root of the repository, recompiles all the servers submodules at
# the commit of the current branch. Assumes `cargo`.

git submodule update --init --recursive

for s in $(ls tests/servers/); do
    cd tests/servers/$s
    cargo build
    cd ../../../
done
