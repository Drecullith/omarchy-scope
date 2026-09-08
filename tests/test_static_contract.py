import json
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StaticContractTests(unittest.TestCase):
    def test_manifest_is_single_quattro_bar_widget(self):
        manifest = json.loads((ROOT / "manifest.json").read_text())
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertEqual(manifest["id"], "io.github.drecullith.scope")
        self.assertEqual(manifest["kinds"], ["bar-widget"])
        self.assertEqual(manifest["entryPoints"]["barWidget"], "Panel.qml")

    def test_runtime_source_has_no_privilege_or_scanner_commands(self):
        helper = (ROOT / "bin" / "scope-helper").read_text().lower()
        qml = (ROOT / "Panel.qml").read_text().lower()
        # Documentation is allowed to say what SCOPE does *not* do. Runtime
        # process command arrays must never invoke scanners, privilege tools,
        # package managers, remote downloaders, or service managers.
        for forbidden in [
            '["sudo"', '["pkexec"', '["systemctl"', '["nmap"', '["arp-scan"',
            '["masscan"', '["curl"', '["wget"', '["pacman"', '["yay"'
        ]:
            self.assertNotIn(forbidden, helper, forbidden)
            self.assertNotIn(forbidden, qml, forbidden)
        self.assertNotIn("shell=true", helper)


    def test_qml_dynamic_text_is_forced_to_plain_text(self):
        qml = (ROOT / "Panel.qml").read_text()
        text_blocks = len(re.findall(r"(?m)^\s*Text\s*\{", qml))
        plain_text_guards = qml.count("textFormat: Text.PlainText")
        self.assertGreater(text_blocks, 0)
        self.assertEqual(plain_text_guards, text_blocks)

    def test_bar_status_handles_vertical_and_security_alert_states(self):
        qml = (ROOT / "Panel.qml").read_text()
        self.assertIn('if (root.vertical) return "S"', qml)
        self.assertIn('return "SCOPE · ROUTE ⚠"', qml)
        self.assertIn('" QUARANTINED"', qml)
        self.assertIn('running: root.active', qml)

    def test_external_ui_actions_use_fixed_system_paths(self):
        qml = (ROOT / "Panel.qml").read_text()
        self.assertIn('["/usr/bin/xdg-open", res.url]', qml)
        self.assertIn('["/usr/bin/wl-copy", String(value)]', qml)
        self.assertNotIn('["xdg-open"', qml)
        self.assertNotIn('["wl-copy"', qml)

    def test_helper_uses_argument_arrays_not_shell_strings(self):
        helper = (ROOT / "bin" / "scope-helper").read_text()
        self.assertIn('subprocess.run(', helper)
        self.assertNotIn('shell=True', helper)
        self.assertNotIn('os.system(', helper)
        self.assertNotIn('subprocess.Popen("', helper)


if __name__ == "__main__":
    unittest.main()
