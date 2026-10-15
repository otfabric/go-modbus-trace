#!/bin/bash
# replaymem.sh <n> <changing|constant|tenth> <port>
#
# Peak RSS of `modbusctl server replay` on an MBCAP file of n FC03 samples.
# MBCAPGEN and MODBUSCTL name the binaries (go build ./cmd/mbcapgen; modbusctl
# built from its checkout). Listens on 127.0.0.1 only, and only until ready.
set -eu
n=$1; prof=$2; port=$3
dir=$(mktemp -d); f=$dir/rep.mbcap
trap 'rm -rf "$dir"' EXIT
"$MBCAPGEN" "$n" "$prof" "$f"
/usr/bin/time -l "$MODBUSCTL" server replay --input "$f" --listen 127.0.0.1 --port "$port" \
	--before-first absent >/dev/null 2>"$dir/time.txt" &
tp=$!
start=$(date +%s)
until lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; do sleep 0.2; done
ready=$(( $(date +%s) - start ))
kill -INT "$(pgrep -P $tp)"; wait $tp || true
peak=$(awk '/maximum resident/ {print $1}' "$dir/time.txt")
echo "samples=$n profile=$prof file_bytes=$(stat -f %z "$f") ready_s=$ready peak_rss_mib=$(( peak / 1048576 ))"
