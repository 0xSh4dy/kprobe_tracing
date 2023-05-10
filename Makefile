compile:
	clang -O2 -g -Wall -I/usr/include -I/usr/include/bpf -o run run.c -lbpf
	clang -O2 -g -target bpf -c prog4.c -o prog4.o