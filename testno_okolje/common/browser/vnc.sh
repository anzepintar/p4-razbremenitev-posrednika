#!/usr/bin/env bash
set -euo pipefail

DISPLAY_NUM="${DISPLAY_NUM:-99}"
GEOMETRY="${VNC_GEOMETRY:-1600x900x24}"
PASSWORD="${VNC_PASSWORD:-diploma}"
WEB_PORT="${VNC_WEB_PORT:-6080}"
export DISPLAY=":$DISPLAY_NUM"

if [ -e "/tmp/.X11-unix/X$DISPLAY_NUM" ]; then
	echo "vnc.sh: zaslon $DISPLAY ze tece"
	exit 0
fi

Xvfb "$DISPLAY" -screen 0 "$GEOMETRY" -nolisten tcp &
for _ in $(seq 1 30); do
	xdpyinfo >/dev/null 2>&1 && break
	sleep 1
done
xdpyinfo >/dev/null 2>&1 || {
	echo "vnc.sh: Xvfb se ni zagnal" >&2
	exit 1
}

openbox &

mkdir -p /root/.vnc
x11vnc -storepasswd "$PASSWORD" /root/.vnc/passwd >/dev/null 2>&1
x11vnc -display "$DISPLAY" -rfbauth /root/.vnc/passwd -rfbport 5900 \
	-forever -shared -noxdamage -quiet &

websockify --web /usr/share/novnc "$WEB_PORT" localhost:5900 &

echo "vnc.sh: zaslon $DISPLAY $GEOMETRY, novnc na $WEB_PORT"
wait
