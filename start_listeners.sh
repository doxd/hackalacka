#!/bin/bash
for LPORT in $(seq 2000 1000 7000); do
    tmux new -d -s "l$LPORT" " while true; do nc -nlvp $LPORT; done;"
done
