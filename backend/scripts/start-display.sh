#!/bin/sh
# Boots the virtual-display stack that makes login-macro recording
# (headless=False Chromium) visible/interactable from the analyst's own
# browser via VNC-in-a-<iframe>, instead of needing a real local display
# or a browser extension. See backend/Dockerfile's comment above the
# xvfb/x11vnc/fluxbox/novnc install for why each piece is here.
#
# Everything below is backgrounded and left running for the container's
# whole lifetime (not spun up per-recording-request) — this is a
# self-hosted, single-analyst-at-a-time tool, so the simplicity of
# "always on" wins over the complexity of lifecycle-managing it per
# request. -nopw: no VNC password: acceptable only because
# docker-compose.yml binds this port to 127.0.0.1, not 0.0.0.0 — it's
# reachable from the analyst's own machine, never the network.
set -e

Xvfb :99 -screen 0 1280x800x24 &
sleep 1

DISPLAY=:99 fluxbox &

x11vnc -display :99 -rfbport 5999 -nopw -forever -shared -quiet &
sleep 1

# --web serves noVNC's bundled static client (vnc_lite.html + core/*.js)
# on the same port as the WebSocket<->VNC proxy, so the frontend just
# points an <iframe> at http://localhost:6080/vnc_lite.html — no
# separate static file server needed.
websockify --web=/usr/share/novnc 6080 localhost:5999 &

# Deliberately not `exec "$@"` — this script is sourced as one `&&`-joined
# step of a larger `sh -c "... && ..."` command line (see
# docker-compose.yml / this Dockerfile's CMD), not used as an ENTRYPOINT
# wrapper. Backgrounded children of a non-interactive `sh -c` child
# process aren't SIGHUP'd when that child exits, so they keep running
# after this script itself returns.
