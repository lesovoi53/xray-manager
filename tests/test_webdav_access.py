import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('access', ROOT/'scripts/webdav-access.py')
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)


class FakeFirewall:
    families = ('iptables', 'ip6tables')
    def __init__(self):
        self.rules = {f: [] for f in self.families}
        self.first = {f: None for f in self.families}
        self.failure = None
        self.calls = []
    def read(self, family):
        return copy.deepcopy(self.rules[family])
    def apply(self, family, old, new, test=False):
        self.calls.append((family, test))
        if (family, test) == self.failure:
            self.failure = None
            raise RuntimeError('Injected firewall failure')
        if not test:
            self.rules[family] = copy.deepcopy(new)
            self.first[family] = new[0] if new else None


class WebdavAccess(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root/'config.env'
        self.config.write_text('WEBDAV_MODE="selfhosted"\nSELFHOSTED_PORT="19080"\nWEBDAV_LISTEN=":28080"\n')
        self.fw = FakeFirewall()
    def change(self, action):
        access.change(action, self.root, self.fw)
    def test_config_matches_runner_listen_precedence_and_multi(self):
        self.assertEqual(access.local_port(self.root), 28080)
        for mode in ('mailru', 'yandex', 'custom', 'server', 'external'):
            self.config.write_text('WEBDAV_MODE='+mode)
            self.assertIsNone(access.local_port(self.root))
        self.config.write_text('WEBDAV_MODE=multi\nMULTI_LOCAL_ENABLED=false')
        self.assertIsNone(access.local_port(self.root))
        self.config.write_text('WEBDAV_MODE=multi\nMULTI_LOCAL_ENABLED=true\nSELFHOSTED_PORT=18081')
        self.assertEqual(access.local_port(self.root),18081)
    def test_forbidden_or_invalid_port_refuses_before_mutation(self):
        for value in ('443', '8443', '0', '65536', 'oops'):
            self.config.write_text('WEBDAV_LISTEN=:'+value)
            with self.assertRaises(ValueError): self.change('blocked')
        self.assertEqual(self.fw.calls, [])
    def test_block_repeat_open_preserve_config_and_backup(self):
        before = self.config.read_bytes()
        self.change('blocked')
        calls = len(self.fw.calls)
        self.change('blocked')
        self.assertEqual(len(self.fw.calls), calls)
        self.change('open')
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(access.read_policy(self.root),'open')
        for family in self.fw.families:
            self.assertEqual(self.fw.rules[family], [access.rule(28080,'open')])
        self.assertEqual(len(list((self.root/'access-backups').glob('*.json'))),2)
    def test_partial_failure_restores_both_families_and_policy(self):
        self.change('blocked')
        before = copy.deepcopy(self.fw.rules)
        self.fw.failure = ('ip6tables', False)
        with self.assertRaises(RuntimeError): self.change('open')
        self.assertEqual(self.fw.rules,before)
        self.assertEqual(access.read_policy(self.root),'blocked')
    def test_preflight_failure_makes_no_changes(self):
        self.fw.failure = ('ip6tables',True)
        with self.assertRaises(RuntimeError): self.change('blocked')
        self.assertEqual(self.fw.rules,{'iptables':[],'ip6tables':[]})
        self.assertFalse((self.root/'access-policy.json').exists())
    def test_sync_after_restart_port_change_and_external_mode(self):
        self.change('blocked')
        self.fw = FakeFirewall()
        self.change('sync')
        self.config.write_text('WEBDAV_MODE=multi\nSELFHOSTED_PORT=28081')
        self.change('sync')
        self.assertEqual(self.fw.rules['iptables'],[access.rule(28081,'blocked')])
        self.config.write_text('WEBDAV_MODE=multi\nMULTI_LOCAL_ENABLED=false')
        self.change('sync')
        self.assertEqual(self.fw.rules['iptables'],[])
        self.assertEqual(access.read_policy(self.root),'blocked')
    def test_sync_unmanaged_and_opening_menu_do_not_change_firewall(self):
        self.change('sync')
        self.assertEqual(self.fw.calls,[])
        with patch.object(access,'ROOT',self.root), patch.object(access,'local_port',return_value=28080), patch('builtins.input',return_value='0'), patch('sys.argv',['helper','menu']), patch.object(access,'change') as change:
            access.main()
            change.assert_not_called()
    def test_own_rule_must_precede_other_accept_rules(self):
        self.change('blocked')
        self.fw.first['iptables'] = ['-A','INPUT','-j','ACCEPT']
        self.change('sync')
        self.assertEqual(self.fw.first['iptables'],access.rule(28080,'blocked'))
    def test_install_and_start_hook_include_helper(self):
        self.assertIn('scripts/webdav-access.py', (ROOT/'install.sh').read_text())
        self.assertIn('ExecStartPre=+/usr/bin/python3 /usr/local/share/x-manager/scripts/webdav-access.py sync', (ROOT/'systemd/webdav-tunnel.service').read_text())


if __name__ == '__main__':
    unittest.main()
