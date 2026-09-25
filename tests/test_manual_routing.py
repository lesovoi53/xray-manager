"""Exercise real Bash menu handlers against disposable configs, never real services."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ManualRouting(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mita = self.root / 'mita.json'
        self.dns = [self.root / name for name in ('cotten.toml', 'master.toml')]
        self.mita.write_text(json.dumps({'users': [{'name': 'keep', 'password': 'fixture'}],
                                         'portBindings': [{'port': 2020, 'protocol': 'TCP'}]}))
        for path in self.dns:
            path.write_text('USE_EXTERNAL_SOCKS5 = false\nFORWARD_IP = "127.0.0.1"\nFORWARD_PORT = 10808\nENCRYPTION_KEY = "fixture"\n')
        for path in [self.mita] + self.dns:
            path.chmod(0o640)
        mock = self.root / 'systemctl'
        mock.write_text('#!/bin/sh\necho "$*" >> "$TEST_CALLS"\n'
                        'case "$1" in is-active) test "${TEST_STOPPED:-0}" = 0;; restart) test "${TEST_FAIL:-0}" = 0;; esac\n')
        mock.chmod(0o755)

    def run_menu(self, kind, choice='1', port='23456', fail=False, stopped=False):
        source = (ROOT / 'bin/x-manager').read_text()
        names = ['xm_update_socks_route', 'mieru_manage_routing' if kind == 'mieru' else 'dns_change_routing']
        functions = []
        for name in names:
            match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
            if match:
                functions.append(match[0])
        script = '\n'.join(functions) + '''
clear() { :; }
sleep() { :; }
show_mieru_header() { :; }
get_mieru_routing() { echo direct; }
get_dns_routing() { echo direct; }
get_active_dns_engine() { echo cottendns; }
restart_mieru_and_verify() { systemctl restart mita; }
MIERU_CONFIG_FILE="$TEST_ROOT/mita.json"
COTTEN_CONFIG_FILE="$TEST_ROOT/cotten.toml"
MASTERDNS_CONFIG_FILE="$TEST_ROOT/master.toml"
''' + names[-1]
        env = dict(os.environ, PATH=str(self.root) + ':' + os.environ['PATH'],
                   TEST_ROOT=str(self.root), TEST_CALLS=str(self.root/'calls'),
                   XRAY_SOCKS_PORT=port, TEST_FAIL='1' if fail else '0', TEST_STOPPED='1' if stopped else '0')
        return subprocess.run(['bash', '-c', script], input=choice+'\n', text=True,
                              capture_output=True, env=env, timeout=15)

    def test_mieru_uses_saved_port_and_preserves_users(self):
        result = self.run_menu('mieru')
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(self.mita.read_text())
        self.assertEqual(value['egress']['proxies'][0]['port'], 23456)
        self.assertEqual(value['users'][0]['password'], 'fixture')
        self.assertEqual(self.mita.stat().st_mode & 0o777, 0o640)

    def test_dns_writes_numeric_saved_port_in_both_configs(self):
        result = self.run_menu('dns')
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in self.dns:
            value = tomllib.loads(path.read_text())
            self.assertEqual(value['FORWARD_PORT'], 23456)
            self.assertIs(value['USE_EXTERNAL_SOCKS5'], True)
            self.assertEqual(value['ENCRYPTION_KEY'], 'fixture')

    def test_invalid_ports_leave_files_untouched(self):
        for kind in ('mieru', 'dns'):
            for port in ('443', '8443', 'bad', '65536'):
                before = [p.read_bytes() for p in [self.mita]+self.dns]
                result = self.run_menu(kind, port=port)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(before, [p.read_bytes() for p in [self.mita]+self.dns])

    def test_bad_dns_config_does_not_partially_write_first(self):
        self.dns[1].write_text('broken = [')
        before = self.dns[0].read_bytes()
        result = self.run_menu('dns')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.dns[0].read_bytes(), before)

    def test_restart_failure_restores_files_without_success(self):
        for kind in ('mieru', 'dns'):
            before = [p.read_bytes() for p in [self.mita]+self.dns]
            result = self.run_menu(kind, fail=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(before, [p.read_bytes() for p in [self.mita]+self.dns])
            self.assertNotIn('✓', result.stdout)

    def test_direct_keeps_saved_port_and_keys(self):
        for kind in ('mieru', 'dns'):
            self.assertEqual(self.run_menu(kind).returncode, 0)
            self.assertEqual(self.run_menu(kind, '2').returncode, 0)
        self.assertNotIn('egress', json.loads(self.mita.read_text()))
        for path in self.dns:
            value = tomllib.loads(path.read_text())
            self.assertFalse(value['USE_EXTERNAL_SOCKS5'])
            self.assertEqual(value['FORWARD_PORT'], 23456)

    def test_bad_mieru_config_is_not_replaced(self):
        self.mita.write_text('{invalid')
        self.assertNotEqual(self.run_menu('mieru').returncode, 0)
        self.assertEqual(self.mita.read_text(), '{invalid')

    def test_stopped_service_and_backups_are_preserved(self):
        before = self.mita.read_bytes()
        self.assertEqual(self.run_menu('mieru', stopped=True).returncode, 0)
        self.assertNotIn('restart', (self.root/'calls').read_text())
        backups = list(self.root.glob('.x-manager-route-backup-*/mita.json'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertEqual(backups[0].parent.stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
