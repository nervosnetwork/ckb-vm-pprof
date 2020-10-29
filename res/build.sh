set -e

if [ -z "$RISCV" ]; then
    echo "Environment variable is not set: RISCV"
    exit
fi

build() {
    $RISCV/bin/riscv64-unknown-elf-gcc -g -o res/$1 res/$1.c
    $RISCV/bin/riscv64-unknown-elf-objdump -M no-aliases -d res/$1 > res/$1.objdump
    $RISCV/bin/riscv64-unknown-elf-readelf -a res/$1 > res/$1.readelf
    dwarfdump res/$1 > res/$1.dwarfdump
}

build fib
build abc
