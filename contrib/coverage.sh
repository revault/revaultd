# Assumes:
#  - you have a postgres DB set up with credentials revault:revault
#  - you have functional tests dependencies installed (likely you are in a venv)

set -ex

if [ -z "$JOBS" ]; then JOBS=1; fi

if ! command -v grcov &>/dev/null; then
    cargo install grcov
fi

cargo clean

LLVM_PROFILE_FILE="revaultd_coverage_%m.profraw" RUSTFLAGS="-Zinstrument-coverage" RUSTDOCFLAGS="$RUSTFLAGS -Z unstable-options --persist-doctests target/debug/doctestbins" cargo +nightly build --all-features
LLVM_PROFILE_FILE="revaultd_coverage_%m.profraw" RUSTFLAGS="-Zinstrument-coverage" RUSTDOCFLAGS="$RUSTFLAGS -Z unstable-options --persist-doctests target/debug/doctestbins" cargo +nightly test --all-features
POSTGRES_PASS=revault POSTGRES_USER=revault pytest -n $JOBS

grcov . --binary-path ./target/debug/ -t html --branch --ignore-not-existing --llvm -o ./target/grcov/
firefox target/grcov/index.html

set +ex
