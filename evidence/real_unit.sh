#!/usr/bin/env bash
# Real systemd --user evidence for PR #16252: a healthy unit relaunches after
# the stale-asset watchdog fires; a venv broken mid-install stays up instead.
set -uo pipefail
UNIT=kirocrew.service
log() { echo; echo "=== $* ==="; }
mainpid() { systemctl --user show -p MainPID --value "$UNIT"; }
journal() { journalctl --user -u "$UNIT" --no-pager -o short-precise "$@"; }
wait_up() {
  for _ in $(seq 1 90); do
    if journal | grep -q "Kiro Crew gateway starting" && [ "$(mainpid)" != 0 ]; then return 0; fi
    sleep 2
  done
  echo "gateway did not come up"; journal | tail -80; return 1
}

DIST="$PWD/src/kiro_crew/static/dist"
python3.12 -m venv /tmp/kcvenv
/tmp/kcvenv/bin/pip install -q -e . >/tmp/pip.log 2>&1 || { tail -40 /tmp/pip.log; exit 1; }
mkdir -p "$DIST" && echo '<!doctype html><title>kc</title>' > "$DIST/index.html"

log "render the unit with the product's own generator (user scope)"
export KIROCREW_SERVICE_BIN=/tmp/kcvenv/bin/kirocrew
mkdir -p ~/.config/systemd/user
/tmp/kcvenv/bin/python -c 'from kiro_crew.service import linux; print(linux.render_unit(user_scope=True), end="")' > ~/.config/systemd/user/$UNIT
grep -E '^(ExecStart|Restart|Environment="KIROCREW_SERVICE_MANAGED)' ~/.config/systemd/user/$UNIT
systemctl --user daemon-reload
systemctl --user start "$UNIT"
wait_up || exit 1
systemctl --user show -p ExecStart -p MainPID -p NeedDaemonReload "$UNIT"

log "CASE 1: healthy install, bundle pruned -> watchdog exits, systemd relaunches"
P1=$(mainpid); echo "MainPID before: $P1"
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
rm -rf "$DIST"
NEW=""
for _ in $(seq 1 75); do
  sleep 2; P=$(mainpid)
  if [ "$P" != 0 ] && [ "$P" != "$P1" ]; then NEW=$P; break; fi
done
journal --since "$SINCE" | grep -E "Stale-asset|static assets|supervisor|gateway starting|Main process exited|Scheduled restart|Started " || true
echo "MainPID after: ${NEW:-unchanged}"
[ -n "$NEW" ] || { echo "CASE 1 FAILED: no relaunch"; journal | tail -60; exit 1; }
echo "CASE 1 OK: relaunched as pid $NEW"

log "re-arm: restore the bundle and restart (a gateway that boots without it treats it as a dev install)"
mkdir -p "$DIST" && echo '<!doctype html><title>kc</title>' > "$DIST/index.html"
systemctl --user restart "$UNIT"
sleep 5; wait_up || exit 1

log "CASE 2: venv broken mid-install (kiro_crew no longer importable), bundle pruned -> stays up"
P2=$(mainpid); echo "MainPID before: $P2"
SITE=$(/tmp/kcvenv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
ls "$SITE" | grep -iE 'editable|kiro' || true
mkdir -p /tmp/removed && mv "$SITE"/__editable__*kiro* "$SITE"/*kiro_crew*.pth /tmp/removed/ 2>/dev/null || true
( cd / && /tmp/kcvenv/bin/python -c 'import kiro_crew.cli' ) 2>&1 | tail -1
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
rm -rf "$DIST"
sleep 150
journal --since "$SINCE" | grep -E "Stale-asset|static assets|supervisor|stays up|could not" || true
P=$(mainpid); echo "MainPID after: $P"
if [ "$P" = "$P2" ] && journal --since "$SINCE" | grep -q "stays up on its loaded code"; then
  echo "CASE 2 OK: refused relaunch logged, gateway still pid $P"
else
  echo "CASE 2 FAILED"; journal | tail -80; exit 1
fi
