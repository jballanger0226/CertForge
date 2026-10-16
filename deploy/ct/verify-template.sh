#!/usr/bin/env bash
# Checks a built template: structure first, then boots it with systemd-nspawn and asks it for /healthz.
#   sudo deploy/ct/verify-template.sh dist/certforge_<version>_amd64.tar.zst
set -euo pipefail
T="${1:?usage: verify-template.sh <template.tar.zst>}"
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
W="$(mktemp -d /var/tmp/certforge-verify.XXXXXX)"
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null || true; sleep 2; rm -rf "$W"; }
trap cleanup EXIT

case "$T" in *.tar.zst) ;; *) echo "Proxmox templates must be .tar.zst (or .tar.gz/.xz)" >&2; exit 1;; esac
zstd -t -q "$T"
mkdir "$W/rootfs"
zstd -dc "$T" | tar --numeric-owner -C "$W/rootfs" -xf -
R="$W/rootfs"

# Also written as a GitHub annotation, so the reason shows on the run page without opening the log.
fail() { echo "FAIL: $*" >&2; echo "::error title=Template check failed::${*//$'\n'/%0A}"; exit 1; }
tail_log() { tail -n 40 "$1" | sed 's/\r//; s/\x1b\[[0-9;]*m//g' | tr '\n' '|'; }
grep -q '^ID=debian' "$R/etc/os-release"          || fail "no Debian /etc/os-release"
[ -x "$R/sbin/init" ] || [ -x "$R/usr/lib/systemd/systemd" ] || fail "no init"
[ -x "$R/opt/certforge/venv/bin/python" ]          || fail "venv missing"
[ -f "$R/opt/certforge/app/server.py" ]            || fail "app missing"
[ -L "$R/etc/systemd/system/multi-user.target.wants/certforge.service" ] || fail "service not enabled"
[ -z "$(ls -A "$R/var/lib/certforge")" ]           || fail "data directory is not empty (would leak a CA into every clone)"
[ ! -s "$R/etc/machine-id" ]                       || fail "machine-id baked in"
ls "$R"/etc/ssh/ssh_host_* >/dev/null 2>&1         && fail "SSH host keys baked in"
uid=$(awk -F: '$1=="certforge"{print $3}' "$R/etc/passwd")      # host can't map the container's uids to names
[ "$(stat -c %u:%a "$R/var/lib/certforge")" = "$uid:700" ] || fail "data dir owner/mode: $(stat -c %u:%a "$R/var/lib/certforge") (certforge is uid $uid)"
[ "$(stat -c %a "$R")" = 755 ] || fail "root directory mode is $(stat -c %a "$R"), must be 755"
echo "structure OK"

# Boot it. nspawn shares the runner's network, so the service answers on the runner's port 443.
# The container's own network manager is masked for this test: it would try to reconfigure the
# runner's real interfaces (DHCP is therefore not covered here).
systemctl --root="$R" mask systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service >/dev/null
mkdir -p "$R/var/log/journal"       # persistent journal, so a failed boot can be read afterwards
echo "booting..."
systemd-nspawn -q -D "$R" --boot --register=no --machine=certforge-verify >"$W/boot.log" 2>&1 &
PID=$!
ok=""
for _ in $(seq 1 60); do
  if curl -ks --max-time 3 https://127.0.0.1/healthz 2>/dev/null | grep -qx ok; then ok=1; break; fi
  kill -0 "$PID" 2>/dev/null || fail "container exited: $(tail_log "$W/boot.log")"
  sleep 2
done
if [ -z "$ok" ]; then
  kill "$PID" 2>/dev/null || true; sleep 3
  # Compressed and base64'd so it survives as one annotation line: echo <text> | base64 -d | gunzip
  j=$( { echo "== console"; tail -n 60 "$W/boot.log" | sed 's/\x1b\[[0-9;]*m//g'; echo "== journal"; journalctl -D "$R/var/log/journal" --no-pager -o short-monotonic -n 150 2>&1; } | gzip -9 | base64 -w0)
  echo "::notice title=boot-diagnostics::$j"
  fail "CertForge didn't answer on 443 within 2 minutes (diagnostics are in the boot-diagnostics annotation)"
fi
echo "boot OK: https://127.0.0.1/healthz answered"
