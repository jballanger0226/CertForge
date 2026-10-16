"""Name and address detection, with no real network involved."""
import unittest

from app import netinfo as N
from app.config import Config

IP_OUT = """\
2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0\\       valid_lft 86000sec
2: eth0    inet6 2001:db8:1::50/64 scope global dynamic mngtmpaddr \\       valid_lft 86000sec
2: eth0    inet6 2001:db8:1::dead/64 scope global temporary dynamic \\       valid_lft 86000sec
2: eth0    inet6 2001:db8:1::beef/64 scope global deprecated dynamic \\       valid_lft 0sec
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever
4: wlan0    inet 169.254.3.4/16 scope global wlan0
"""


def dns(table):
    return lambda name: set(table.get(name, ()))


class Parsing(unittest.TestCase):
    def test_resolv(self):
        text = "# generated\nnameserver 10.0.0.1\nsearch lab.example.com corp.example.com ; comment\ndomain lan\n"
        self.assertEqual(N.parse_resolv(text), ["lab.example.com", "corp.example.com", "lan"])
        self.assertEqual(N.parse_resolv("nameserver 1.1.1.1\n"), [])

    def test_leases(self):
        self.assertEqual(N.parse_lease_domains("ADDRESS=10.0.0.5\nDOMAINNAME=Home.Arpa\n"), ["home.arpa"])
        self.assertEqual(N.parse_lease_domains('lease {\n  option domain-name "lab.test";\n}'), ["lab.test"])

    def test_ip_addr_skips_temporary_virtual_and_link_local(self):
        self.assertEqual(N.parse_ip_addr(IP_OUT), ["192.168.1.50", "2001:db8:1::50"])

    def test_org_suggestion(self):
        for domain, want in (("lab.example.com", "Example"), ("example.com", "Example"), ("home.arpa", "Home Lab"),
                             ("", "Home Lab"), ("lan", "Home Lab"), ("corp.acme-widgets.net", "Acme Widgets"),
                             ("localdomain", "Home Lab")):
            self.assertEqual(N.suggest_org(domain), want, domain)


class Building(unittest.TestCase):
    ips = ["192.168.1.50"]

    def test_hostname_plus_dhcp_domain(self):
        i = N.build("nas", "nas", ["lab.example.com"], self.ips, dns({"nas.lab.example.com": {"192.168.1.50"}}))
        self.assertEqual((i.fqdn, i.hostname, i.domain), ("nas.lab.example.com", "nas", "lab.example.com"))
        self.assertEqual(i.names, ["nas.lab.example.com", "nas", "192.168.1.50"])
        self.assertEqual((i.public_host, i.public_note), ("nas.lab.example.com", ""))
        self.assertEqual(i.org, "Example")

    def test_loopback_is_not_a_default_name(self):
        i = N.build("nas", "nas", [], self.ips, dns({}))
        self.assertNotIn("localhost", i.names)
        self.assertNotIn("127.0.0.1", i.names)

    def test_hostname_already_qualified(self):
        i = N.build("Nas.Lab.Test", "", [], self.ips, dns({"nas.lab.test": {"192.168.1.50"}}))
        self.assertEqual(i.fqdn, "nas.lab.test")

    def test_fqdn_from_getfqdn_when_no_search_domain(self):
        i = N.build("nas", "nas.house.test", [], self.ips, dns({"nas.house.test": {"192.168.1.50"}}))
        self.assertEqual(i.fqdn, "nas.house.test")

    def test_name_not_in_dns_falls_back_to_ip_with_a_warning(self):
        i = N.build("nas", "nas", ["lab.test"], self.ips, dns({}))
        self.assertEqual(i.fqdn, "nas.lab.test")
        self.assertEqual(i.public_host, "192.168.1.50")
        self.assertIn("isn't in DNS", i.public_note)

    def test_name_resolving_elsewhere_is_kept_but_flagged(self):
        i = N.build("nas", "nas", ["lab.test"], self.ips, dns({"nas.lab.test": {"10.9.9.9"}}))
        self.assertEqual(i.public_host, "nas.lab.test")
        self.assertIn("10.9.9.9", i.public_note)

    def test_only_an_ip_warns_about_dhcp(self):
        i = N.build("", "", [], self.ips, dns({}))
        self.assertEqual((i.public_host, i.names), ("192.168.1.50", ["192.168.1.50"]))
        self.assertIn("DHCP", i.public_note)

    def test_container_ids_and_useless_domains_are_ignored(self):
        i = N.build("3f2a9c1b7d4e", "3f2a9c1b7d4e", ["localdomain"], ["172.20.0.5"], dns({}))
        self.assertEqual((i.hostname, i.domain, i.fqdn), ("", "", ""))
        self.assertEqual(i.names, ["172.20.0.5"])

    def test_reaching_the_page_by_name_makes_it_the_public_address(self):
        i = N.build("nas", "nas", ["lab.test"], self.ips, dns({}), request_host="certs.lab.test")
        self.assertEqual((i.public_host, i.public_note), ("certs.lab.test", ""))
        # ...but an IP or localhost in the address bar proves nothing
        i = N.build("nas", "nas", ["lab.test"], self.ips, dns({}), request_host="192.168.1.50")
        self.assertEqual(i.public_host, "192.168.1.50")
        i = N.build("nas", "nas", ["lab.test"], self.ips, dns({"nas.lab.test": {"192.168.1.50"}}), request_host="localhost")
        self.assertEqual(i.public_host, "nas.lab.test")

    def test_nothing_known(self):
        i = N.build("", "", [], [], dns({}))
        self.assertEqual((i.names, i.public_host, i.org), ([], "", "Home Lab"))


class Settings(unittest.TestCase):
    def test_secrets_from_files_and_both_required(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "pw").write_text("a-long-admin-password\n")
            (pathlib.Path(d) / "pp").write_text("a-long-ca-passphrase\r\n")
            c = Config.from_env({"CERTFORGE_ADMIN_PASSWORD_FILE": f"{d}/pw", "CERTFORGE_CA_PASSPHRASE_FILE": f"{d}/pp",
                                 "CERTFORGE_SEAL": "true", "CERTFORGE_ORG": " Lab "})
            self.assertEqual((c.auto.admin_password, c.auto.passphrase, c.auto.seal, c.auto.org),
                             ("a-long-admin-password", "a-long-ca-passphrase", True, "Lab"))
        self.assertIsNone(Config.from_env({}).auto)
        with self.assertRaises(SystemExit):
            Config.from_env({"CERTFORGE_ADMIN_PASSWORD": "only-one-of-the-two"})
        with self.assertRaises(SystemExit):
            Config.from_env({"CERTFORGE_ADMIN_PASSWORD_FILE": "/nonexistent", "CERTFORGE_CA_PASSPHRASE": "x"})


if __name__ == "__main__":
    unittest.main()
