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

fail() { echo "FAIL: $*" >&2; exit 1; }
grep -q '^ID=debian' "$R/etc/os-release"          || fail "no Debian /etc/os-release"
[ -x "$R/sbin/init" ] || [ -x "$R/usr/lib/systemd/systemd" ] || fail "no init"
[ -x "$R/opt/certforge/venv/bin/python" ]          || fail "venv missing"
[ -f "$R/opt/certforge/app/server.py" ]            || fail "app missing"
[ -L "$R/etc/systemd/system/multi-user.target.wants/certforge.service" ] || fail "service not enabled"
[ -z "$(ls -A "$R/var/lib/certforge")" ]           || fail "data directory is not empty (would leak a CA into every clone)"
[ ! -s "$R/etc/machine-id" ]                       || fail "machine-id baked in"
ls "$R"/etc/ssh/ssh_host_* >/dev/null 2>&1         && fail "SSH host keys baked in"
[ "$(stat -c %U:%a "$R/var/lib/certforge")" = "certforge:700" ] || fail "data dir owner/mode"
echo "structure OK"

# Boot it. nspawn shares the runner's network, so the service answers on the runner's port 443.
echo "booting..."
systemd-nspawn -q -D "$R" --boot --register=no --machine=certforge-verify >"$W/boot.log" 2>&1 &
PID=$!
ok=""
for _ in $(seq 1 60); do
  if curl -ks --max-time 3 https://127.0.0.1/healthz 2>/dev/null | grep -qx ok; then ok=1; break; fi
  kill -0 "$PID" 2>/dev/null || { cat "$W/boot.log"; fail "container exited"; }
  sleep 2
done
[ -n "$ok" ] || { tail -50 "$W/boot.log"; fail "CertForge didn't answer on 443 within 2 minutes"; }
echo "boot OK: https://127.0.0.1/healthz answered"
