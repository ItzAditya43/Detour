#!/usr/bin/env bash
# Find a Cloudflare WARP endpoint this network lets through.
#
# Tries each address:port against the running Detour tunnel (detour0) and
# reports which ones complete a WireGuard handshake AND carry traffic. Puts
# the original endpoint back when done. Needs root (wg set, ping -I).
#
#   sudo packaging/warp-endpoint-probe.sh
set -uo pipefail

IFACE=detour0
ADDRS=(162.159.192.1 162.159.193.1 188.114.97.1)
PORTS=(2408 500 1701 4500 894 7559 8854)

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
ip link show "$IFACE" >/dev/null 2>&1 || { echo "$IFACE is down: start the tunnel in Detour first"; exit 1; }

PEER=$(wg show "$IFACE" peers | head -1)
ORIG=$(wg show "$IFACE" endpoints | awk '{print $2}' | head -1)
trap 'wg set "$IFACE" peer "$PEER" endpoint "$ORIG"; echo; echo "Restored endpoint $ORIG"' EXIT

echo "Testing ${#ADDRS[@]} addresses x ${#PORTS[@]} ports (about 5s each)..."
WORKING=()
for a in "${ADDRS[@]}"; do
  for p in "${PORTS[@]}"; do
    wg set "$IFACE" peer "$PEER" endpoint "$a:$p"
    before=$(wg show "$IFACE" latest-handshakes | awk '{print $2}')
    # Bound to the tunnel device, so the ping itself travels through WARP.
    if ping -I "$IFACE" -c 2 -W 2 -q 1.1.1.1 >/dev/null 2>&1; then
      printf "  %-22s WORKS\n" "$a:$p"; WORKING+=("$a:$p")
    else
      after=$(wg show "$IFACE" latest-handshakes | awk '{print $2}')
      if [[ "$after" != "$before" && "$after" != 0 ]]; then
        printf "  %-22s handshake only, no data\n" "$a:$p"
      else
        printf "  %-22s blocked\n" "$a:$p"
      fi
    fi
  done
done

echo
if ((${#WORKING[@]})); then
  echo "Working endpoints: ${WORKING[*]}"
else
  echo "No endpoint worked: this network is blocking WARP/WireGuard outright."
fi
