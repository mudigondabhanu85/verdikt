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
#
# Real, live-found failure mode this guards against: this script is
# `&&`-chained ahead of `uv run uvicorn ...` (see docker-compose.yml),
# so its own exit code gates whether the backend container starts at
# all — but every process below is backgrounded with `&`, which is
# exactly what makes a *missing binary* invisible to that exit code:
# `set -e` only sees the `&` itself succeed (launching a background job
# always "succeeds"), never the command-not-found failure inside it.
# Confirmed live: rebuilding this image after xvfb/x11vnc/fluxbox/novnc
# were newly added to the Dockerfile's apt-get list, but *reusing* an
# already-built image from before that change, produced exactly this —
# three silent "not found" lines buried in `docker compose logs`, the
# backend's own /health endpoint (an unrelated app-level check) still
# reporting healthy, and the login-macro recorder completely non-
# functional with nothing surfacing why until an analyst dug through
# container logs. The checks below turn that into a loud, impossible-
# to-miss banner instead — without hard-failing the whole container
# over an optional feature (scanning itself never depends on VNC; the
# standalone browser-extension recorder is a real fallback), since a
# missing-package image bug shouldn't block ~everything else Verdikt
# does.
set -e

_missing=""
for _bin in Xvfb fluxbox x11vnc websockify; do
    if ! command -v "$_bin" >/dev/null 2>&1; then
        _missing="$_missing $_bin"
    fi
done

if [ -n "$_missing" ]; then
    echo "=================================================================="
    echo "ERROR: login-macro recorder display stack cannot start."
    echo "Missing binaries:$_missing"
    echo "This backend image predates their install in Dockerfile — a"
    echo "rebuild is needed (docker compose up --build, not plain"
    echo "'docker compose up' / 'up -d', which reuses the cached image"
    echo "unchanged even after Dockerfile itself has been edited)."
    echo "Everything else (scanning, the API, the standalone browser-"
    echo "extension recorder) is unaffected — only the in-app VNC-"
    echo "streamed 'Record in-browser' option will fail to load."
    echo "=================================================================="
    exit 0
fi

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
sleep 1

# Backgrounding hides a launch failure from `set -e` (see the comment
# above) even when the binary DOES exist — a bad flag, a port already
# in use, etc. would otherwise fail exactly as silently as the missing-
# binary case this script primarily guards against. `pgrep` confirms
# each process is actually alive, not just that its `&` was accepted.
_dead=""
pgrep -x Xvfb >/dev/null 2>&1 || _dead="$_dead Xvfb"
pgrep -x fluxbox >/dev/null 2>&1 || _dead="$_dead fluxbox"
pgrep -x x11vnc >/dev/null 2>&1 || _dead="$_dead x11vnc"
pgrep -x websockify >/dev/null 2>&1 || _dead="$_dead websockify"

if [ -n "$_dead" ]; then
    echo "=================================================================="
    echo "ERROR: login-macro recorder display stack failed to start."
    echo "Not running after launch:$_dead"
    echo "Check the lines above this banner for the real error from each"
    echo "process. Everything else (scanning, the API, the standalone"
    echo "browser-extension recorder) is unaffected."
    echo "=================================================================="
else
    echo "Login-macro recorder display stack is up (VNC on :6080)."
fi

# Deliberately not `exec "$@"` — this script is sourced as one `&&`-joined
# step of a larger `sh -c "... && ..."` command line (see
# docker-compose.yml / this Dockerfile's CMD), not used as an ENTRYPOINT
# wrapper. Backgrounded children of a non-interactive `sh -c` child
# process aren't SIGHUP'd when that child exits, so they keep running
# after this script itself returns.
