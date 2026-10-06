#!/bin/sh
# Laboratory sample (benign). Starts one short child process and waits for it.
# No file writes, no network, nothing persists.
set -eu
sleep 2 &
wait
echo "child process finished"
