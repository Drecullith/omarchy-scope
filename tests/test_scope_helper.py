import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin" / "scope-helper"
LOADER = importlib.machinery.SourceFileLoader("scope_helper", str(HELPER))
SPEC = importlib.util.spec_from_loader("scope_helper", LOADER)
scope_helper = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(scope_helper)


def nmap_xml(hosts):
    chunks = ['<?xml version="1.0"?>', '<nmaprun scanner="nmap">']
    for host in hosts:
        chunks.append('<host>')
        chunks.append('<status state="up"/>')
        chunks.append(f'<address addr="{host["ip"]}" addrtype="ipv4"/>')
        if host.get("hostname"):
            chunks.append(f'<hostnames><hostname name="{host["hostname"]}" type="user"/></hostnames>')
        chunks.append('<ports>')
        for port, service in host.get("ports", []):
            chunks.append(
                f'<port protocol="tcp" portid="{port}"><state state="open"/>'
                f'<service name="{service}"/><script id="ignored" output="UNTRUSTED"/></port>'
            )
        chunks.append('</ports></host>')
    chunks.append('</nmaprun>')
    return ''.join(chunks)


class ScopeHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_home = Path(self.tmp.name) / "state"
        self.env = mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.state_home)}, clear=False)
        self.env.start()
        self.route = mock.patch.object(
            scope_helper,
            "_route_lookup",
            return_value={
                "known": True,
                "target": "10.10.11.42",
                "dev": "tun0",
                "gateway": "",
                "source": "10.10.14.7",
            },
        )
        self.route.start()

    def tearDown(self):
        self.route.stop()
        self.env.stop()
        self.tmp.cleanup()

    def start(self, scope="10.10.11.42"):
        args = type("Args", (), {"name": "Boardlight", "kind": "lab", "scope": scope})()
        return scope_helper.cmd_start(args)


    def test_doctor_is_read_only_and_reports_optional_commands(self):
        result = scope_helper.cmd_doctor(type("Args", (), {})())
        self.assertEqual(result["status"], "ok")
        self.assertIn("python", result["checks"])
        self.assertIn("ip", result["checks"])
        self.assertIn("xdgOpen", result["checks"])
        self.assertIn("wlCopy", result["checks"])

    def test_scope_exact_network_exclusion_and_wildcard(self):
        rules = scope_helper.parse_scope_text(
            "10.10.11.42\n10.20.0.0/16\n*.example.com\n!10.20.1.13\n!admin.example.com"
        )
        self.assertTrue(scope_helper.scope_decision("10.10.11.42", rules)["allowed"])
        self.assertTrue(scope_helper.scope_decision("10.20.9.9", rules)["allowed"])
        self.assertFalse(scope_helper.scope_decision("10.20.1.13", rules)["allowed"])
        self.assertTrue(scope_helper.scope_decision("portal.example.com", rules)["allowed"])
        self.assertFalse(scope_helper.scope_decision("example.com", rules)["allowed"])
        self.assertFalse(scope_helper.scope_decision("admin.example.com", rules)["allowed"])

    def test_scope_rejects_implicit_network_widening(self):
        with self.assertRaises(scope_helper.ScopeError):
            scope_helper.parse_scope_text("10.10.11.42/24")

    def test_start_captures_read_only_route_baseline(self):
        result = self.start()
        self.assertEqual(result["status"], "ok")
        state = scope_helper.load_state()
        self.assertTrue(state["active"])
        self.assertEqual(state["engagement"]["primaryTarget"], "10.10.11.42")
        self.assertEqual(state["engagement"]["routeBaseline"]["dev"], "tun0")
        state_path = self.state_home / "omarchy-scope" / "state.json"
        mode = stat.S_IMODE(state_path.stat().st_mode)
        self.assertEqual(mode, 0o600)


    def test_primary_target_change_is_scope_checked_and_rebaselines(self):
        self.start("10.10.11.0/24\n!10.10.11.13")
        with mock.patch.object(
            scope_helper,
            "_route_lookup",
            return_value={"known": True, "target": "10.10.11.99", "dev": "tun9", "gateway": "", "source": "10.0.0.2"},
        ):
            result = scope_helper.cmd_primary(type("Args", (), {"target": "10.10.11.99"})())
        self.assertEqual(result["target"], "10.10.11.99")
        state = scope_helper.load_state()["engagement"]
        self.assertEqual(state["primaryTarget"], "10.10.11.99")
        self.assertEqual(state["routeBaseline"]["dev"], "tun9")

        with self.assertRaises(scope_helper.ScopeError):
            scope_helper.cmd_primary(type("Args", (), {"target": "10.10.11.13"})())

    def test_route_guard_detects_change(self):
        self.start()
        with mock.patch.object(
            scope_helper,
            "_route_lookup",
            return_value={
                "known": True,
                "target": "10.10.11.42",
                "dev": "wlan0",
                "gateway": "192.168.1.1",
                "source": "192.168.1.50",
            },
        ):
            args = type("Args", (), {"target": "10.10.11.42"})()
            result = scope_helper.cmd_route(args)
        self.assertEqual(result["route"]["verdict"], "changed")
        self.assertEqual(result["route"]["baseline"]["dev"], "tun0")

    def test_mixed_nmap_import_quarantines_out_of_scope(self):
        self.start()
        xml = nmap_xml([
            {"ip": "10.10.11.42", "hostname": "boardlight.htb", "ports": [(22, "ssh"), (80, "http")]},
            {"ip": "192.168.1.20", "hostname": "printer.local", "ports": [(445, "microsoft-ds")]},
        ])
        scan = Path(self.tmp.name) / "mixed.xml"
        scan.write_text(xml, encoding="utf-8")
        args = type("Args", (), {"path": str(scan)})()
        result = scope_helper.cmd_import_nmap(args)
        self.assertEqual(result["allowed"], 1)
        self.assertEqual(result["quarantined"], 1)
        self.assertEqual(result["services"], 2)

        state = scope_helper.load_state()["engagement"]
        self.assertEqual(state["targets"][0]["address"], "10.10.11.42")
        self.assertEqual([s["port"] for s in state["targets"][0]["services"]], [22, 80])
        self.assertEqual(state["quarantine"][0]["address"], "192.168.1.20")
        # Script output is intentionally never imported.
        self.assertNotIn("UNTRUSTED", json.dumps(state))

    def test_nmap_hostname_cannot_authorize_an_ip(self):
        self.start("boardlight.htb")
        scan = Path(self.tmp.name) / "hostonly.xml"
        scan.write_text(
            nmap_xml([{"ip": "10.10.11.42", "hostname": "boardlight.htb", "ports": [(80, "http")]}]),
            encoding="utf-8",
        )
        result = scope_helper.cmd_import_nmap(type("Args", (), {"path": str(scan)})())
        self.assertEqual(result["allowed"], 0)
        self.assertEqual(result["quarantined"], 1)

    def test_nmap_rejects_doctype_and_entity_declarations(self):
        self.start()
        scan = Path(self.tmp.name) / "unsafe.xml"
        scan.write_text(
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun/>',
            encoding="utf-8",
        )
        with self.assertRaises(scope_helper.ScopeError) as ctx:
            scope_helper.cmd_import_nmap(type("Args", (), {"path": str(scan)})())
        self.assertEqual(ctx.exception.code, "import-unsafe-xml")

    def test_scope_checked_url_generation_and_ipv6_brackets(self):
        self.start("10.10.11.42\n2001:db8::15")
        result = scope_helper.cmd_url(type("Args", (), {"target": "10.10.11.42", "scheme": "http", "port": "80"})())
        self.assertTrue(result["allowed"])
        self.assertEqual(result["url"], "http://10.10.11.42/")

        result6 = scope_helper.cmd_url(type("Args", (), {"target": "2001:db8::15", "scheme": "https", "port": "8443"})())
        self.assertEqual(result6["url"], "https://[2001:db8::15]:8443/")

        denied = scope_helper.cmd_url(type("Args", (), {"target": "192.168.1.5", "scheme": "http", "port": "80"})())
        self.assertFalse(denied["allowed"])
        self.assertNotIn("url", denied)

    def test_timeline_is_local_and_bounded(self):
        self.start()
        for i in range(scope_helper.MAX_TIMELINE + 20):
            scope_helper.cmd_note(type("Args", (), {"text": f"note-{i}"})())
        timeline = scope_helper.load_state()["engagement"]["timeline"]
        self.assertEqual(len(timeline), scope_helper.MAX_TIMELINE)
        self.assertEqual(timeline[-1]["message"], f"note-{scope_helper.MAX_TIMELINE + 19}")


    def test_nmap_symlink_is_refused(self):
        self.start()
        real = Path(self.tmp.name) / "real.xml"
        real.write_text(nmap_xml([{"ip": "10.10.11.42", "ports": [(80, "http")]}]), encoding="utf-8")
        link = Path(self.tmp.name) / "link.xml"
        link.symlink_to(real)
        with self.assertRaises(scope_helper.ScopeError):
            scope_helper.cmd_import_nmap(type("Args", (), {"path": str(link)})())

    def test_oversized_import_is_refused_before_parse(self):
        self.start()
        scan = Path(self.tmp.name) / "huge.xml"
        with scan.open("wb") as handle:
            handle.truncate(scope_helper.MAX_NMAP_BYTES + 1)
        with self.assertRaises(scope_helper.ScopeError) as ctx:
            scope_helper.cmd_import_nmap(type("Args", (), {"path": str(scan)})())
        self.assertEqual(ctx.exception.code, "import-too-large")

    def test_reimport_merges_services_without_duplicates(self):
        self.start()
        scan1 = Path(self.tmp.name) / "one.xml"
        scan1.write_text(nmap_xml([{"ip": "10.10.11.42", "ports": [(22, "ssh"), (80, "http")]}]), encoding="utf-8")
        scan2 = Path(self.tmp.name) / "two.xml"
        scan2.write_text(nmap_xml([{"ip": "10.10.11.42", "ports": [(80, "http"), (443, "https")]}]), encoding="utf-8")
        scope_helper.cmd_import_nmap(type("Args", (), {"path": str(scan1)})())
        scope_helper.cmd_import_nmap(type("Args", (), {"path": str(scan2)})())
        services = scope_helper.load_state()["engagement"]["targets"][0]["services"]
        self.assertEqual([(x["port"], x["service"]) for x in services], [(22, "ssh"), (80, "http"), (443, "https")])

    def test_state_symlink_is_refused(self):
        self.start()
        state_file = self.state_home / "omarchy-scope" / "state.json"
        outside = Path(self.tmp.name) / "outside.json"
        outside.write_text('{"schemaVersion":1,"active":false,"engagement":null}', encoding="utf-8")
        state_file.unlink()
        state_file.symlink_to(outside)
        with self.assertRaises(scope_helper.ScopeError):
            scope_helper.load_state()

    def test_excluded_target_url_is_denied_even_when_network_matches(self):
        self.start("10.10.11.0/24\n!10.10.11.13")
        denied = scope_helper.cmd_url(type("Args", (), {"target": "10.10.11.13", "scheme": "http", "port": "80"})())
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["scope"]["excludedBy"], ["!10.10.11.13"])

    def test_end_stops_active_session_without_destroying_last_state(self):
        self.start()
        scope_helper.cmd_end(type("Args", (), {})())
        state = scope_helper.load_state()
        self.assertFalse(state["active"])
        self.assertEqual(state["engagement"]["name"], "Boardlight")
        self.assertTrue(state["engagement"].get("endedAt"))


if __name__ == "__main__":
    unittest.main()
