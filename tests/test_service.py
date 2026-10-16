"""Service behaviour that needs no network or server process."""
import tempfile
import unittest
from pathlib import Path

from app import netinfo
from app.config import Config
from app.service import Service


def make(data: Path, hostnames="") -> Service:
    return Service(Config(data=data, bind="127.0.0.1", https_port=8443, http_port=0, hostnames=hostnames, setup_token=None))


class BootstrapCertificate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = make(Path(self.tmp.name))
        self.addrs = ["192.168.1.50"]
        # The network, as DHCP currently describes it
        self.svc.net = lambda request_host="": netinfo.build("nas", "nas", ["lab.test"], self.addrs, lambda n: set(), request_host)

    def test_is_reused_while_the_names_stay_the_same(self):
        crt, _, kind = self.svc.tls_files()
        first = Path(crt).read_bytes()
        self.assertEqual(kind, "bootstrap")
        self.svc.tls_files()
        self.assertEqual(Path(crt).read_bytes(), first)
        self.assertFalse(self.svc.bootstrap_stale())

    def test_is_replaced_when_dhcp_hands_out_a_new_address(self):
        crt, _, _ = self.svc.tls_files()
        first = Path(crt).read_bytes()
        self.addrs[:] = ["192.168.1.99"]
        self.assertTrue(self.svc.bootstrap_stale())
        self.svc.tls_files()
        self.assertNotEqual(Path(crt).read_bytes(), first)
        self.assertFalse(self.svc.bootstrap_stale())

    def test_configured_hostnames_win_over_detection(self):
        svc = make(Path(self.tmp.name) / "other", hostnames="a.test,10.0.0.9")
        svc.net = self.svc.net
        self.assertEqual(svc.initial_names().splitlines(), ["a.test", "10.0.0.9"])
        self.assertEqual(svc.default_public_host(), ("a.test", ""))

    def test_detected_names_and_public_address(self):
        self.assertEqual(self.svc.initial_names().splitlines(), ["nas.lab.test", "nas", "192.168.1.50"])
        host, note = self.svc.default_public_host()
        self.assertEqual(host, "192.168.1.50")
        self.assertIn("isn't in DNS", note)


if __name__ == "__main__":
    unittest.main()
