# eBPF-Redirector
An XDP program to redirect traffic

## Useful Commands
Reference to some commands for the project

### `bpf_printk()` Pipe
```
# Acquire debug output from trace_pipe
cat /sys/kernel/debug/tracing/trace_pipe
```

### `bpftool` Commands
```
# Shows all loaded xdp programs
sudo bpftool prog show | grep "xdp" -A 2
```

### `ip` Commands

```
# Load the "xdp" section to a device
sudo ip link set dev lo xdpgeneric obj ebpf-redirector.o sec xdp

# Show device info (include XDP information)
sudo ip link show dev lo

# Remove the XDP program from device
sudo ip link set dev lo xdpgeneric off 
```
*Good for plug and play smaller programs, but does not support eBPF maps*

### `llvm-dump` Commands
```
# Dump the section from the object file
llvm-dump -S <file.o> --section=<section>
```

### `netperf` Commands
```
netperf -host <forwarderIP> -port <forwarderPort> -testname <testname> -testlen <sec> 
```

## Dependencies
Tested and developed on
```
Ubuntu 22.04.1 LTS x86_64
```
Relevant packages
```
$ sudo apt install clang llvm-dev libelf1 libelf-dev zlib1g-dev libbpf-dev
```