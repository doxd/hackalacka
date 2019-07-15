#!/bin/bash
for LPORT in $(seq 2000 1000 6000); do
    tmux kill-session -t "l$LPORT"
done