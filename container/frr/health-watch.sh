#!/bin/sh
# Simple watcher: if HAProxy stats is unreachable, shut neighbor; otherwise, enable.
# Requires vtysh inside this container and HAProxy stats on 127.0.0.1:8404.

BGP_ASN="65000"
NEIGH="UP1"
STATS_URL="http://127.0.0.1:8404/stats"
STATE_FILE="/run/frr/.haproxy-state"

set_state() {
    echo "$1" > "$STATE_FILE"
}

current_state() {
    [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "unknown"
}

while true; do
    if wget -qO- "$STATS_URL" >/dev/null 2>&1; then
        if [ "$(current_state)" != "up" ]; then
            vtysh -c "configure terminal" -c "router bgp $BGP_ASN" -c "no neighbor $NEIGH shutdown"
            set_state "up"
        fi
    else
        if [ "$(current_state)" != "down" ]; then
            vtysh -c "configure terminal" -c "router bgp $BGP_ASN" -c "neighbor $NEIGH shutdown"
            set_state "down"
        fi
    fi
    sleep 5
done
