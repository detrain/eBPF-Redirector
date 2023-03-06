# eBPF-Redirector
An XDP program to redirect traffic

## Useful Commands

### `bpftool` Commands:
```

```

### `ip` Commands:

```
# Load the "xdp" section to a device
sudo ip link set dev lo xdpgeneric obj ebpf-redirector.o sec xdp

# Show device info (include XDP information)
sudo ip link show dev lo

# Remove the XDP program from device
sudo ip link set dev lo xdpgeneric off 
```
*Good for plug and play smaller programs, but does not support eBPF maps*

## Dependencies
`Ubuntu 22.04.1 LTS 86_64`
```
$ sudo apt install clang-14 llvm-14-tools llvm-14-dev libelf1 libelf-dev zlib1g-dev libbpf-dev
```

[bpf_tool](https://github.com/libbpf/bpftool)
