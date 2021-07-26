set -e

cargo build --release
./target/release/ckb-vm-pprof --bin $1 > /tmp/flamegraph.txt 2>&1
cat /tmp/flamegraph.txt | inferno-flamegraph > /tmp/flamegraph.svg
