#!/bin/bash

tmux new -d -s smb "impacket-smbserver dump /dev/shm"
