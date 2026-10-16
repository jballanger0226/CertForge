#!/usr/bin/env bash
# Builds a Proxmox LXC container template (.tar.zst) containing CertForge on Debian.
# Needs root, debootstrap and zstd; the build machine needs network access.
#   sudo deploy/ct/build-template.sh <version> [output-dir] [debian-suite]
# Output: <output-dir>/certforge_<version>_amd64.tar.zst  (+ .sha256)
# Install on Proxmox: copy to /var/lib/vz/template/cache/, then create a container from it.
set -euo pipefail

VERSION="${1:?usage: build-template.sh <version> [output-dir] [debian-suite]}"
OUT="$(realpath -m "${2:-dist}")"
SUITE="${3:-trixie}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT="$(mktemp -d /var/tmp/certforge-rootfs.XXXXXX)"
chmod 755 "$ROOT"      # mktemp makes it 0700, which would become the container's / and lock every non-root user out
NAME="certforge_${VERSION}_amd64.tar.zst"

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
cleanup() {
  for m in dev/pts dev proc sys; do umount "$ROOT/$m" 2>/dev/null || true; done
  rm -rf "$ROOT"
}
trap cleanup EXIT

PKGS=systemd,systemd-sysv,dbus,iproute2,iputils-ping,openssl,ca-certificates,python3,python3-venv,libpam-systemd,less,nano,procps
echo ">> debootstrap $SUITE"
debootstrap --variant=minbase --include="$PKGS" "$SUITE" "$ROOT" http://deb.debian.org/debian

echo ">> install CertForge"
install -d -m 755 "$ROOT/opt/certforge"
cp -r "$SRC/app" "$SRC/requirements.txt" "$ROOT/opt/certforge/"
find "$ROOT/opt/certforge" -name __pycache__ -prune -exec rm -rf {} +
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
mount -t proc proc "$ROOT/proc"
chroot "$ROOT" /bin/sh -e <<'CH'
useradd --system --home-dir /var/lib/certforge --shell /usr/sbin/nologin certforge
install -d -m 700 -o certforge -g certforge /var/lib/certforge
python3 -m venv /opt/certforge/venv
/opt/certforge/venv/bin/pip install --no-cache-dir --quiet -r /opt/certforge/requirements.txt
CH
umount "$ROOT/proc"

install -m 644 "$SRC/deploy/ct/certforge.service" "$ROOT/etc/systemd/system/certforge.service"
install -m 755 "$SRC/deploy/ct/certforge-code" "$ROOT/usr/local/bin/certforge-code"
install -m 644 "$SRC/deploy/ct/motd" "$ROOT/etc/motd"
install -d "$ROOT/etc/systemd/network"
install -m 644 "$SRC/deploy/ct/network-fallback.network" "$ROOT/etc/systemd/network/zz-dhcp-fallback.network"
printf '# CERTFORGE_HOSTNAMES=certforge.lan,10.0.0.5   # names for the first web certificate (auto-detected if unset)\n' > "$ROOT/etc/certforge.env"
echo certforge > "$ROOT/etc/hostname"
printf '%s\n' "$VERSION" > "$ROOT/opt/certforge/VERSION"

systemctl --root="$ROOT" enable certforge.service systemd-networkd.service systemd-networkd-wait-online.service >/dev/null
systemctl --root="$ROOT" mask getty-static.service >/dev/null 2>&1 || true

echo ">> clean up"
chroot "$ROOT" apt-get clean
rm -rf "$ROOT"/var/lib/apt/lists/* "$ROOT"/var/cache/apt/* "$ROOT"/usr/share/doc/* "$ROOT"/usr/share/man/* "$ROOT"/tmp/* "$ROOT"/var/log/*.log "$ROOT"/var/log/apt
: > "$ROOT/etc/machine-id"          # regenerated on first boot, so clones don't share one
: > "$ROOT/etc/resolv.conf"         # Proxmox fills this in
rm -f "$ROOT"/etc/ssh/ssh_host_* 2>/dev/null || true

echo ">> pack $NAME"
install -d "$OUT"
tar --numeric-owner --xattrs --acls --one-file-system -C "$ROOT" -cf - . | zstd -T0 -19 -q -f -o "$OUT/$NAME"
(cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256")
ls -lh "$OUT/$NAME"
