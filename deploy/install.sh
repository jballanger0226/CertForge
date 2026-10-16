#!/usr/bin/env bash
# Installs CertForge as a systemd service on Debian/Ubuntu/RHEL-family Linux.
# Run as root from the project folder:  sudo ./deploy/install.sh [hostname,other-name,10.0.0.5]
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run this as root (sudo)." >&2; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/opt/certforge
DATA=/var/lib/certforge
NAMES="${1:-}"      # optional: names for the first web certificate. Without it, CertForge works them out from DHCP and DNS.

if command -v apt-get >/dev/null; then
  apt-get update -qq && apt-get install -y -qq python3 python3-venv openssl
elif command -v dnf >/dev/null; then
  dnf install -y -q python3 openssl
fi
command -v python3 >/dev/null && command -v openssl >/dev/null || { echo "python3 and openssl are required." >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "Python 3.11 or newer is required." >&2; exit 1; }

id certforge >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin certforge
install -d -m 755 "$DEST"
install -d -m 700 -o certforge -g certforge "$DATA"

cp -r "$SRC/app" "$SRC/requirements.txt" "$DEST/"
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install --quiet --upgrade pip
"$DEST/venv/bin/pip" install --quiet -r "$DEST/requirements.txt"

if [ ! -f /etc/certforge.env ]; then
  umask 077
  {
    [ -n "$NAMES" ] && printf 'CERTFORGE_HOSTNAMES=%s\n' "$NAMES"
    echo '# Zero-touch setup: set both of these (or use CERTFORGE_ADMIN_PASSWORD_FILE / CERTFORGE_CA_PASSPHRASE_FILE)'
    echo '# and the CA is created on the next start with no wizard. See the README.'
    echo '# CERTFORGE_ADMIN_PASSWORD='
    echo '# CERTFORGE_CA_PASSPHRASE='
    echo '# A separate signing CA for ACME (intermediate = under your root, root = its own root). The passphrase unlocks it at every start:'
    echo '# CERTFORGE_ACME_CA=intermediate'
    echo '# CERTFORGE_ACME_CA_PASSPHRASE='
  } > /etc/certforge.env
fi
install -m 755 "$SRC/deploy/ct/certforge-code" /usr/local/bin/certforge-code
install -m 644 "$SRC/deploy/certforge.service" /etc/systemd/system/certforge.service
systemctl daemon-reload
systemctl enable --now certforge

echo
FIRST="${NAMES%%,*}"; [ -n "$FIRST" ] || FIRST="$(hostname -f 2>/dev/null || hostname)"
echo "CertForge is starting. To finish setup, open https://$FIRST/ and enter the setup code (also: certforge-code):"
sleep 3
journalctl -u certforge --no-pager -n 40 | grep -i -A4 "needs one-time setup" || echo "  (run: journalctl -u certforge | grep -i -A4 'one-time setup')"
