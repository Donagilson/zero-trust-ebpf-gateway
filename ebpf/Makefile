CLANG ?= clang
ARCH ?= x86

.PHONY: all clean

all: filter.bpf.o

filter.bpf.o: filter.bpf.c
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

clean:
	rm -f filter.bpf.o
