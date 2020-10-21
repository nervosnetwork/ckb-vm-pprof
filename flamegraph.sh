set -e

cargo build --release
./target/release/ckb-vm-pprof --bin $1 > flamegraph.txt 2>&1
cat flamegraph.txt | inferno-flamegraph > flamegraph.svg
