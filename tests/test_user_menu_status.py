"""Render the real TUI with synthetic API responses; never modify subscriptions."""
import json
import os
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class UserMenuStatus(unittest.TestCase):
    def render(self, fields):
        source = (ROOT / 'bin/x-manager').read_text()
        match = re.search(r'^edit_sub_user\(\) \{\n.*?(?=^[A-Za-z_]\w*\(\) \{|\Z)', source, re.M | re.S)
        payload = dict(id='fixture-user', nickname='Fixture', enabled=True, revision=13, total_uris=6, **fields)
        script = match.group() + '\nclear() { :; }; curl() { printf "%s" "$RESPONSE"; }; edit_sub_user fixture-user\n'
        result = subprocess.run(['bash', '-c', script], input='0\n', text=True, capture_output=True,
                                env=dict(os.environ, RESPONSE=json.dumps(payload)), timeout=10)
        self.assertEqual(result.returncode, 0)
        return result.stdout

    def test_detail_response_enabled_flags_and_counts(self):
        output = self.render(dict(openflux_enabled=True, openflux_groups_count=2,
                                  webdav_enabled=True, webdav_connections_count=1))
        self.assertIn('[Включен (2 групп)]', output)
        self.assertIn('[Включен (1 подкл.)]', output)

    def test_explicit_false_wins_over_legacy_fallback(self):
        output = self.render(dict(openflux_enabled=False, webdav_enabled=False,
                                  protocols=dict(openflux=True, webdav=True)))
        self.assertNotIn('[Включен', output)

    def test_legacy_response_still_supported(self):
        output = self.render(dict(protocols=dict(openflux=True, webdav=True), counts=dict(openflux=2, webdav=1)))
        self.assertIn('[Включен (2 групп)]', output)
        self.assertIn('[Включен (1 подкл.)]', output)


if __name__ == '__main__':
    unittest.main()
