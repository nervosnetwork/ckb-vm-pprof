main:
	docker run --rm -v `pwd`:/code nervos/ckb-riscv-gnu-toolchain:bionic-20210804 bash -c "cd /code && make main_docker"

main_docker:
	riscv64-unknown-elf-gcc -g -o abc abc.c
	riscv64-unknown-elf-gcc -g -o fib fib.c
	riscv64-unknown-elf-gcc -g -o sprintf sprintf.c
	riscv64-unknown-elf-gcc -g -o outofmemory outofmemory.c
