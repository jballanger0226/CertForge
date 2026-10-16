# CertForge

[![CI](https://github.com/jballanger0226/CertForge/actions/workflows/ci.yml/badge.svg)](https://github.com/jballanger0226/CertForge/actions/workflows/ci.yml)

A small private certificate authority with a web page on port 443. Type a name, get a signed certificate. No OpenSSL command line.

- Two-level chain: a root CA and an online intermediate CA that signs your certificates.
- Two ways to get a certificate:
  - **Make one for me**: you give names or IP addresses, you get a `.p12` (key + cert + chain, with a password) or a PEM `.zip` for nginx, Apache and the like.
  - **Sign my request**: paste or upload a CSR, you get a `.cer`, `.der`, full-chain `.pem` or `.p7b`.
- A public **Trust page** (`/trust`) hands out the root and intermediate certificates and shows how to trust them on Windows, macOS, iOS (profile), Android, Linux and Firefox.
- Revocation with a CRL, certificates are listed with expiry warnings, and the web page's own certificate renews itself.

## Run it with Docker

```bash
docker compose up -d --build
docker logs certforge        # shows the one-time setup code
```

Edit `CERTFORGE_HOSTNAMES` in `docker-compose.yml` first to the names or IPs people will use to reach the server. Then open `https://<that name>/`, enter the setup code, pick an admin password and a CA passphrase. Your browser will warn once, because the CA doesn't exist yet. After setup, download the root from the page and trust it (the Trust page has the steps), and the warning goes away.

Ports 443 and 80 are both used. 443 is the web UI. 80 only serves the public CA files and revocation list (clients fetch these over plain HTTP by design) and redirects everything else to 443.

## Run it as a service on a VM

On a Debian, Ubuntu or RHEL-family machine with Python 3.11+:

```bash
sudo ./deploy/install.sh certforge.lan,10.0.0.5
```

This creates a `certforge` user, installs into `/opt/certforge`, keeps data in `/var/lib/certforge` (mode 700), and starts a hardened systemd unit that can bind 443 without running as root. The setup code is in `journalctl -u certforge`. To use it as a VM template, run the installer, stop the service and empty `/var/lib/certforge` before you snapshot, so every clone creates its own CA and setup code on first boot. Set each clone's names in `/etc/certforge.env`. Never snapshot a machine that has finished setup; the clones would share one CA.

## Run it as a Proxmox container

Each tagged release (`v*`) has a `certforge_<version>_amd64.tar.zst` Debian container template attached. Build the latest one yourself from the **Actions** tab (Proxmox CT template, then Run workflow) and download it from the run's artifacts.

1. Put the file in `/var/lib/vz/template/cache/` on the Proxmox host, or upload it under *local > CT Templates*.
2. Create a container from it (*Create CT > Template*). 1 core, 512 MB RAM and 2 GB disk are plenty. An unprivileged container is fine.
3. Start it and open `https://<container IP or name>/`. Get the setup code from the console with `certforge-code`.

Back up `/var/lib/certforge` inside the container (or use Proxmox backups). Settings live in `/etc/certforge.env`, including the optional zero-touch setup values. The template is built on Debian 13, so you need a Proxmox VE release that supports it.

## Running it without a container or service manager

```bash
pip install -r requirements.txt
CERTFORGE_DATA=./data sudo -E python -m app.server     # or give python CAP_NET_BIND_SERVICE
```

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `CERTFORGE_DATA` | `/data` | Where the CA and database live. **Back this up.** |
| `CERTFORGE_HOSTNAMES` | detected | Names/IPs for the web page's first certificate. Set it in Docker, where CertForge can't see your network |
| `CERTFORGE_HTTPS_PORT` | `443` | |
| `CERTFORGE_HTTP_PORT` | `80` | `0` turns the plain-HTTP helper off |
| `CERTFORGE_BIND` | `0.0.0.0` | |
| `CERTFORGE_SETUP_TOKEN` | random | Pick your own first-run setup code |
| `CERTFORGE_ADMIN_PASSWORD` / `_FILE` | | Zero-touch setup: admin password (12+ characters) |
| `CERTFORGE_CA_PASSPHRASE` / `_FILE` | | Zero-touch setup: CA passphrase (12+ characters, different from the password) |
| `CERTFORGE_ORG` | from the domain | Zero-touch setup: CA name |
| `CERTFORGE_SEAL` | `false` | Zero-touch setup: ask for the passphrase after every restart |
| `CERTFORGE_PUBLIC_HOST` | detected | Zero-touch setup: address written into certificates for CA downloads and revocation checks |
| `CERTFORGE_KEY_TYPE`, `CERTFORGE_ROOT_YEARS`, `CERTFORGE_INT_YEARS`, `CERTFORGE_PERMITTED` | `ec-p384`, 20, 10, none | Zero-touch setup: same as the wizard's Advanced section |

## What CertForge works out for itself

On a VM or Proxmox container with DHCP, CertForge reads the host name, the DHCP search domain and the interface addresses, and pre-fills the setup page:

- **Names for the web certificate:** `host.domain`, the short host name and the IP addresses (not `localhost`). If you open the page by some other name, that is added too.
- **Address for CA downloads and revocation checks:** the name you used to reach the page, or `host.domain` if DNS knows it. If it isn't in DNS yet, CertForge uses the IP address and warns that DHCP can change it.
- **CA name:** suggested from the domain (`lab.example.com` becomes "Example").
- Until setup is finished, the temporary certificate follows DHCP: a new address or name is picked up within a minute.

So the wizard is just the setup code and two passwords; **Detected settings** is there if something looks wrong. In Docker the container can't see your network's names, so set `CERTFORGE_HOSTNAMES`.

## Zero-touch setup

To create the CA with nobody at the keyboard (templates, Ansible, cloud-init, Compose), set both secrets:

```bash
CERTFORGE_ADMIN_PASSWORD_FILE=/run/secrets/admin   # or CERTFORGE_ADMIN_PASSWORD
CERTFORGE_CA_PASSPHRASE_FILE=/run/secrets/ca       # or CERTFORGE_CA_PASSPHRASE
```

On the first start the CA is created from those and the detected names, and the web page is already using its CA-issued certificate. Nothing is written to the log except that it happened. There is no setup page for anyone else to find. Afterwards the secrets are no longer needed: remove them from the environment. Bad values (too short, same password and passphrase) stop the server with a clear message.

CertForge never generates and stores these secrets itself. Keeping the CA passphrase in a file next to the encrypted key would defeat the encryption. With `CERTFORGE_SEAL=true` the passphrase is still asked for after every restart.

## How your keys are protected

- CA private keys are stored encrypted (PKCS#8, AES-256, PBKDF2 with 600,000 rounds) under the **CA passphrase** you choose at setup. The passphrase is never stored.
- **Root key custody.** The root is only needed to renew the intermediate. After setup, use the CA page to download an encrypted backup of the root key, then remove it from the server. Store the backup offline.
- **Locked mode.** Tick "Ask for the passphrase after every restart" at setup and the intermediate key can't be read until you enter the passphrase after each restart. Otherwise the CA starts on its own, which is easier but means the passphrase protects only the files at rest.
- Private keys for certificates made by "Make one for me" are **never written to disk**. They live in memory for 15 minutes so you can download them, then they're gone.
- The intermediate can be limited to certain domains or networks (name constraints), so a leaked intermediate can't be used to impersonate the whole internet.
- Sign-in: scrypt-hashed password, strict cookies, CSRF checks, login throttling, a strict Content-Security-Policy.

## Backups

Back up the whole `CERTFORGE_DATA` folder (the `certforge-data` volume in Docker) and keep the CA passphrase separately. Without both, the CA can't be restored.

## Good to know

- Certificates last up to 825 days and never outlive the intermediate. Browsers reject longer ones.
- Keep the server's clock right (use NTP). Certificates are only valid within their dates.
- A CSR only gives the CA names and a public key. Any extensions in the request, including `CA:TRUE`, are ignored.
- Anyone who can sign in to the web page can issue certificates, so keep it on a network you trust and use a strong admin password. There is a single admin account.
- Revocation only helps clients that check the CRL. Many browsers don't check private CAs' lists.
- Certificates carry `http://<public address>/pki/...` pointers to the CA files and CRL. Set the public address on the CA page to the name clients actually use.

## Checks that run on GitHub

Every push and pull request runs: Python and shell lint, Dockerfile and compose validation, the engine and end-to-end tests, a dependency vulnerability audit, and a Docker build that starts the container with the same restrictions as `docker-compose.yml` and checks it is healthy, not running as root, and redirects port 80 to 443. Pull requests that touch the app or `deploy/ct/` also build the Proxmox template and boot it to confirm CertForge answers. Dependabot keeps pip, Docker and Actions versions current.

## Tests

```bash
python -m unittest tests.test_ca     # CA engine, checked against the OpenSSL command line
sudo python -m unittest tests.test_e2e   # full app on real ports 443 and 80
```
