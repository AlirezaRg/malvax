#!/bin/sh
# Laboratory sample (benign). Creates one file under /tmp and prints a marker.
# It does not persist, does not use the network, and does not touch any other path.
set -eu
out="/tmp/malvax-lab-test.txt"
printf 'MALVAX_LAB_TMP\n' > "$out"
echo "lab sample ran"
