"""Works out what this server is called on the network, so setup can pre-fill itself.

The pure functions (parse_*, build, suggest_org) take their inputs as arguments so they can be
tested without a network; detect() gathers the real inputs: hostname, the DHCP search domain,
the interface addresses, and whether the server's own name is actually in DNS.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Search domains that mean "nothing useful" (typical of images and containers).
IGNORED_DOMAINS = {"localdomain", "localhost", "invalid"}
# Interfaces that only exist inside this machine, so their addresses mean nothing to other devices.
VIRTUAL_IFACES = ("docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "lxcbr", "lxdbr", "podman", "tailscale")
CONTAINER_ID = re.compile(r"^[0-9a-f]{12}([0-9a-f]{52})?$")
GENERIC_SUFFIXES = {"com", "net", "org", "io", "co", "us", "uk", "de", "lan", "home", "local", "internal",
                    "intranet", "corp", "arpa", "private", "localdomain"}


@dataclass
class NetInfo:
    hostname: str = ""                 # short host name, "" when it's unusable (container id, localhost)
    domain: str = ""                   # DHCP / search domain
    fqdn: str = ""                     # host name plus domain, "" when we couldn't tell
    ips: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)   # what the web certificate should cover
    public_host: str = ""              # what to write into issued certificates as the CA's address
    public_note: str = ""              # shown next to it when it deserves a warning
    org: str = "Home Lab"              # suggested CA name


# ---- parsing helpers (pure) ---------------------------------------------------------------
def parse_resolv(text: str) -> list[str]:
    """Search domains from /etc/resolv.conf, in order ('domain' and 'search' lines)."""
    out: list[str] = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split(";", 1)[0].split()
        if len(parts) >= 2 and parts[0] in ("search", "domain"):
            for d in parts[1:]:
                d = d.strip(".").lower()
                if d and d not in out:
                    out.append(d)
    return out


def parse_lease_domains(text: str) -> list[str]:
    """Domain from a systemd-networkd lease (DOMAINNAME=x) or a dhclient lease (option domain-name "x";)."""
    out = []
    for m in re.finditer(r'^DOMAINNAME=(\S+)|option\s+domain-name\s+"([^"]+)"', text, re.M):
        d = (m.group(1) or m.group(2)).strip(".").lower()
        if d and d not in out:
            out.append(d)
    return out


def parse_ip_addr(text: str) -> list[str]:
    """Addresses from `ip -o addr show scope global`, skipping temporary or deprecated IPv6 and virtual interfaces."""
    v4: list[str] = []
    v6: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] not in ("inet", "inet6"):
            continue
        iface = parts[1].rstrip(":")
        if iface.startswith(VIRTUAL_IFACES):
            continue
        if any(flag in parts for flag in ("temporary", "deprecated", "tentative", "dadfailed")):
            continue
        try:
            ip = ipaddress.ip_interface(parts[3]).ip
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        (v4 if ip.version == 4 else v6).append(str(ip))
    return [*dict.fromkeys(v4), *dict.fromkeys(v6)]


def suggest_org(domain: str) -> str:
    """'lab.example.com' -> 'Example'. Falls back to 'Home Lab' when the domain says nothing."""
    labels = [l for l in domain.lower().strip(".").split(".") if l]
    while labels and labels[-1] in GENERIC_SUFFIXES and len(labels) > 1:
        labels.pop()
    if not labels or labels[-1] in GENERIC_SUFFIXES:
        return "Home Lab"
    name = re.sub(r"[^a-z0-9]+", " ", labels[-1]).strip().title()
    return name[:40] or "Home Lab"


def build(hostname: str, fqdn_guess: str, domains: list[str], ips: list[str],
          resolve: Callable[[str], set[str]], request_host: str = "") -> NetInfo:
    """Combine what we know. `resolve(name)` returns the addresses DNS gives for a name (empty if none)."""
    raw = hostname.strip().strip(".").lower()
    short = raw.split(".")[0]
    if short in ("", "localhost") or CONTAINER_ID.match(short):
        short = ""
    domain = next((d for d in domains if d not in IGNORED_DOMAINS), "")

    fqdn = ""
    guess = fqdn_guess.strip().strip(".").lower()
    if short and "." in raw and raw.split(".", 1)[1] not in IGNORED_DOMAINS:
        fqdn = raw
    elif short and "." in guess and guess.split(".")[0] == short and guess.split(".", 1)[1] not in IGNORED_DOMAINS:
        fqdn = guess
    elif short and domain:
        fqdn = f"{short}.{domain}"

    names = [n for n in dict.fromkeys([fqdn, short, *ips]) if n]
    info = NetInfo(hostname=short, domain=domain, fqdn=fqdn, ips=list(ips), names=names, org=suggest_org(domain))

    rh = request_host.strip().lower()
    reached_by_name = rh and rh != "localhost" and not _is_ip(rh)
    if reached_by_name:
        # You got here by typing this name, so it works for the people who'll use the CA too.
        info.public_host = rh
    elif fqdn:
        addrs = resolve(fqdn)
        if addrs:
            info.public_host = fqdn
            if ips and not (addrs & set(ips)):
                info.public_note = (f"{fqdn} points to {', '.join(sorted(addrs))}, which isn't one of this server's own "
                                    "addresses. That's fine for a NAT or load-balancer address; otherwise check your DNS.")
        elif ips:
            info.public_host = ips[0]
            info.public_note = (f"{fqdn} isn't in DNS yet, so CertForge will use the IP address. A DHCP address can change: "
                                "reserve it in your router, or switch this to a name once DNS knows it.")
    if not info.public_host and ips:
        info.public_host = ips[0]
        info.public_note = ("Only an IP address was found. A DHCP address can change, so reserve it in your router "
                            "or enter a DNS name here.")
    if not info.public_host and short:
        info.public_host = short
    return info


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


# ---- gathering the real inputs --------------------------------------------------------------
def _read(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def local_domains() -> list[str]:
    out = parse_resolv(_read("/etc/resolv.conf"))
    for d in (Path("/run/systemd/netif/leases"), Path("/var/lib/dhcp")):
        try:
            for f in sorted(d.iterdir())[:20]:
                if f.is_file() and f.stat().st_size < 65536:
                    out += [x for x in parse_lease_domains(f.read_text(errors="replace")) if x not in out]
        except OSError:
            pass
    return out


def local_ips() -> list[str]:
    try:
        p = subprocess.run(["ip", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=3)
        ips = parse_ip_addr(p.stdout)
        if ips:
            return ips
    except (OSError, subprocess.SubprocessError):
        pass
    ips: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))          # sends nothing; just asks which interface would be used
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return [i for i in ips if not i.startswith(("0.", "127."))]


_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns")
_dns_cache: dict[str, tuple[float, set[str]]] = {}
_dns_lock = threading.Lock()


def resolve(name: str, timeout: float = 3.0, ttl: float = 60.0) -> set[str]:
    """Addresses DNS (or /etc/hosts) gives for a name. Empty when it doesn't resolve or takes too long."""
    now = time.monotonic()
    with _dns_lock:
        hit = _dns_cache.get(name)
        if hit and now - hit[0] < ttl:
            return hit[1]
    try:
        fut = _pool.submit(socket.getaddrinfo, name, None)
        found = {ai[4][0].split("%")[0] for ai in fut.result(timeout=timeout)}
    except (OSError, FutureTimeout):
        found = set()
    with _dns_lock:
        _dns_cache[name] = (now, found)
    return found


def detect(request_host: str = "") -> NetInfo:
    host = socket.gethostname()
    try:
        guess = socket.getfqdn()
    except OSError:
        guess = ""
    return build(host, guess, local_domains(), local_ips(), resolve, request_host)
