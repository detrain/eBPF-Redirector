#!/bin/bash

APP=../ebpf-redirector/.output/xdp.bpf.o

usage()
{
    echo "Usage: $0 <InterfaceName>" 1>&2
    exit 1
}

if [ $# -ne 1 ]
then
    usage
fi

# Unload any programs if present
ip link set dev $1 xdpgeneric off

# Load program
ip link set dev $1 xdpgeneric obj ${APP} sec xdp_redirect && echo "Section loaded to $1 successfully"