# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
CLANG ?= clang-14
CFLAGS = -O2 -g -Wall -target bpf

.PHONY: ebpf_redirector
ebpf_redirector: ebpf_redirector.bpf.c ebpf_redirector.h 
	$(CLANG) $(CFLAGS) -c ebpf_redirector.bpf.c -o ebpf_redirector.o 

.PHONY: clean
clean:
	rm -f ebpf_redirector.o
