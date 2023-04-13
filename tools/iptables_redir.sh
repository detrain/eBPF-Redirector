#!/bin/bash

iptables -t nat -A PREROUTING -s 10.0.2.4 -p tcp --dport 8080 -j DNAT --to-destination 10.0.2.5:80
iptables -t nat -A POSTROUTING -j MASQUERADE