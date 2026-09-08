import json
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

    def test_helper_uses_argument_arrays_not_shell_strings(self):
        helper = (ROOT / "bin" / "scope-helper").read_text()
        self.assertIn('subprocess.run(', helper)
        self.assertNotIn('shell=True', helper)
        self.assertNotIn('os.system(', helper)
        self.assertNotIn('subprocess.Popen("', helper)


if __name__ == "__main__":
    unittest.main()
