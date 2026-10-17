#!/bin/bash
# Install siempl as a systemd *user* service so it starts at boot and restarts on failure.
#
#   scripts/install_service.sh              # install + enable + start (port 8765, loopback only)
#   scripts/install_service.sh --port 9000
#   scripts/install_service.sh --lan        # bind 0.0.0.0 instead of 127.0.0.1 (the API has no auth: think first)
#   scripts/install_service.sh --dry-run    # print the unit, change nothing
#   scripts/install_service.sh --uninstall
#
# Env overrides: SIEMPL_PYTHON (interpreter, default .venv/bin/python), SIEMPL_UNIT_DIR (default ~/.config/systemd/user).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${SIEMPL_PYTHON:-$REPO/.venv/bin/python}"
UNIT_DIR="${SIEMPL_UNIT_DIR:-$HOME/.config/systemd/user}"
PORT=8765
EXTRA_ARGS=""
DRY=0
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift ;;
    --lan) EXTRA_ARGS="$EXTRA_ARGS --host" ;;
    --no-collectors) EXTRA_ARGS="$EXTRA_ARGS --no-collectors" ;;
    --dry-run) DRY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$UNINSTALL" = 1 ]; then
  systemctl --user disable --now siempl.service 2>/dev/null || true
  rm -f "$UNIT_DIR/siempl.service"
  systemctl --user daemon-reload
  echo "siempl.service removed"
  exit 0
fi

[ -x "$PYTHON" ] || { echo "python not found at $PYTHON (create the venv, or set SIEMPL_PYTHON)" >&2; exit 1; }

render() {
  sed -e "s|@REPO@|$REPO|g" -e "s|@PYTHON@|$PYTHON|g" -e "s|@PORT@|$PORT|g" \
      -e "s|@EXTRA_ARGS@|${EXTRA_ARGS# }|g" "$REPO/deploy/siempl.service.in"
}

if [ "$DRY" = 1 ]; then render; exit 0; fi

mkdir -p "$UNIT_DIR"
render > "$UNIT_DIR/siempl.service"
systemctl --user daemon-reload
systemctl --user enable --now siempl.service
# Without linger a user service only runs while you are logged in.
loginctl enable-linger "$USER" 2>/dev/null || echo "note: could not enable linger; service will stop when you log out" >&2
echo "siempl.service installed -> http://127.0.0.1:$PORT  (logs: journalctl --user -u siempl -f)"
