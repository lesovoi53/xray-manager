import copy
import importlib
import io
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
tui = importlib.import_module('tuna-groups')


class SpeedtestMenuTests(unittest.TestCase):
    def test_consecutive_links_keep_exact_uris_and_reject_duplicates(self):
        uris = ['vless://11111111-2222-4333-8444-55555555555%d@192.0.2.%d:24443?security=reality&encryption=none#Server%d' % (i, i, i) for i in range(1, 4)]
        state = {'profiles': []}
        with patch('builtins.input', side_effect=['', uris[0], '', uris[0], uris[1], uris[2], '']), redirect_stdout(io.StringIO()) as output:
            selected = tui.add_servers(state, 'VPN')
        self.assertEqual(len(selected), 3)
        self.assertEqual([p['uri'] for p in state['profiles']], uris)
        self.assertIn('уже добавлен', output.getvalue())
        for uri in uris:
            self.assertNotIn(uri, output.getvalue())
        with patch('builtins.input', side_effect=['@1', '*', '']), redirect_stdout(io.StringIO()):
            self.assertEqual(tui.add_servers(state, 'VPN'), selected)

    def test_presets_need_only_one_number_and_never_fetch(self):
        for number, size in [('1', 1048576), ('2', 10485760)]:
            with self.subTest(number=number), patch('builtins.input', side_effect=[number]) as read, patch.object(tui.urllib.request, 'urlopen') as fetch, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(tui.test_url('SPEEDTEST'), 'https://speed.cloudflare.com/__down?bytes=%d' % size)
                self.assertEqual(read.call_count, 1)
                fetch.assert_not_called()
                self.assertIn('[3] Свой HTTPS URL', output.getvalue())

    def test_custom_url_is_explicit_and_validated(self):
        with patch('builtins.input', side_effect=['3', '', 'http://invalid.test', 'https://[broken', 'https://example.test/file#fragment', 'https://example.test/file']), redirect_stdout(io.StringIO()):
            self.assertEqual(tui.test_url('SPEEDTEST'), 'https://example.test/file')

    def test_cancel_presets_and_custom(self):
        for answers in (['0'], ['3', '0']):
            with patch('builtins.input', side_effect=answers), redirect_stdout(io.StringIO()), self.assertRaises(tui.Invalid):
                tui.test_url('SPEEDTEST')

    def test_existing_custom_url_can_be_kept(self):
        group = dict(tui.DEFAULTS, type='SPEEDTEST', testUrl='https://example.test/existing')
        original = copy.deepcopy(group)
        field = list(tui.LABELS).index('testUrl') + 1
        with patch('builtins.input', side_effect=[str(field), '3', '0']), redirect_stdout(io.StringIO()):
            tui.settings(group)
        self.assertEqual(group, original)

    def test_cancel_type_change_preserves_entire_group(self):
        group = dict(tui.DEFAULTS, name='Test', family='VPN', type='URL_TEST', testUrl='https://example.test/probe', probeMethod='HEAD')
        original = copy.deepcopy(group)
        with patch('builtins.input', side_effect=['4', '2', '0']), redirect_stdout(io.StringIO()), self.assertRaises(tui.Invalid):
            tui.edit({}, group)
        self.assertEqual(group, original)


if __name__ == '__main__':
    unittest.main()
