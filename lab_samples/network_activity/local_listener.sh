#!/bin/sh
# Laboratory sample (benign). Starts a local HTTP listener on 127.0.0.1 only, fetches from it,
# and stops it. It never contacts any address other than loopback.
set -eu
python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
pid=$!
sleep 2
python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18080/', timeout=5).read()"
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
echo "local listener round-trip done"
