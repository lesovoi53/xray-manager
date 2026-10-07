"""Render the real TUI with synthetic API responses; never modify subscriptions."""
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class UserMenuStatus(unittest.TestCase):
    LINKS = [
        'snell://v6-a@remote.test:446?version=6#Saved-v6-a',
        'snell://v5-a@remote.test:445?version=5&custom=a%2Bb#Saved-v5-a',
        'snell://v6-b@remote.test:447?version=6#Saved-v6-b',
        'snell://v4-a@remote.test:444?version=4#Saved-v4-a',
    ]

    def render(self, fields, actions='0\n'):
        source = (ROOT / 'bin/x-manager').read_text()
        match = re.search(r'^edit_sub_user\(\) \{\n.*?(?=^[A-Za-z_]\w*\(\) \{|\Z)', source, re.M | re.S)
        payload = dict(id='fixture-user', nickname='Fixture', enabled=True, revision=13, total_uris=6, **fields)
        script = match.group() + '\nclear() { :; }; curl() { printf "%s" "$RESPONSE"; }; snell6_tool() { printf "SNELL6:%s\\n" "$*"; }; edit_sub_user fixture-user\n'
        result = subprocess.run(['bash', '-c', script], input=actions, text=True, capture_output=True,
                                env=dict(os.environ, RESPONSE=json.dumps(payload)), timeout=10)
        self.assertEqual(result.returncode, 0)
        return result.stdout

    def edit_snell(self, actions, incoming='', *, put_exit=0, put_response=None, latest=None):
        source = (ROOT / 'bin/x-manager').read_text()
        match = re.search(r'^edit_sub_user\(\) \{\n.*?(?=^[A-Za-z_]\w*\(\) \{|\Z)', source, re.M | re.S)
        user = dict(id='fixture-user', nickname='Fixture', enabled=True, revision=13,
                    total_uris=len(self.LINKS), snell='\n'.join(self.LINKS), snell_uris=self.LINKS)
        script = match.group() + r'''
clear() { :; }
sleep() { :; }
collect_multi_uris() { printf '%s' "$COLLECTED"; }
curl() {
    local first="$1" method=GET data=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -X) method="$2"; shift;;
            -d) data="$2"; shift;;
        esac
        shift
    done
    if [ "$method" = PUT ]; then
        printf '%s' "$data" > "$WRITE_PATH"
        printf '%s' "$PUT_RESPONSE"
        return "$PUT_EXIT"
    fi
    if [ "$first" = -fsS ]; then
        printf '%s' "$LATEST"
    else
        printf '%s' "$RESPONSE"
    fi
}
edit_sub_user fixture-user
'''
        with tempfile.TemporaryDirectory() as directory:
            write_path = pathlib.Path(directory, 'written.json')
            result = subprocess.run(['bash', '-c', script], input=actions, text=True, capture_output=True,
                                    env=dict(os.environ, RESPONSE=json.dumps(user), COLLECTED=incoming,
                                             WRITE_PATH=str(write_path), PUT_EXIT=str(put_exit),
                                             PUT_RESPONSE=json.dumps(put_response if put_response is not None else user),
                                             LATEST=json.dumps(dict(user, snell='\n'.join(latest)) if latest is not None else user)),
                                    timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            written = json.loads(write_path.read_text()) if write_path.exists() else None
        return written, result.stdout + result.stderr

    def test_v5_view_excludes_v6_and_cancel_never_writes(self):
        written, output = self.edit_snell('2\n1\n0\n0\n')
        self.assertIsNone(written)
        for link in self.LINKS[1::2]:
            self.assertIn(link, output)
        for link in self.LINKS[::2]:
            self.assertNotIn(link, output)

    def test_v5_clear_preserves_v6_order_and_only_patches_snell(self):
        written, output = self.edit_snell('2\n1\n3\ny\n0\n')
        self.assertEqual(written, {'snell_uri': '\n'.join(self.LINKS[::2])})
        self.assertIn('успешно обновлены', output)

    def test_v5_replace_preserves_v6_and_exact_supplied_foreign_links(self):
        new_links = ['snell://foreign5@host.test:443?version=5&custom=x%2By#Custom%20name',
                     'snell://foreign4@host.test:444?version=4#Other']
        written, _ = self.edit_snell('2\n1\n1\n0\n', '\n'.join(new_links))
        self.assertEqual(written, {'snell_uri': '\n'.join([self.LINKS[0], *new_links, self.LINKS[2]])})

    def test_v5_add_preserves_all_existing_links_and_order(self):
        new_link = 'snell://foreign@host.test:443?version=5#Exact-foreign'
        written, _ = self.edit_snell('2\n1\n2\n0\n', new_link)
        self.assertEqual(written, {'snell_uri': '\n'.join([*self.LINKS, new_link])})

    def test_v5_edits_preserve_v6_saved_during_interactive_input(self):
        newer = [*self.LINKS, 'snell://newer@remote.test:448?version=6#Saved-later']
        written, _ = self.edit_snell('2\n1\n3\ny\n0\n', latest=newer)
        self.assertEqual(written, {'snell_uri': '\n'.join([self.LINKS[0], self.LINKS[2], newer[-1]])})

    def test_v5_empty_input_and_declined_clear_are_noops(self):
        for actions in ('2\n1\n1\n0\n', '2\n1\n2\n0\n', '2\n1\n3\nn\n0\n'):
            with self.subTest(actions=actions):
                self.assertIsNone(self.edit_snell(actions)[0])

    def test_v5_editor_rejects_v6_input_without_changing_existing_links(self):
        for option in ('1', '2'):
            written, output = self.edit_snell('2\n1\n' + option + '\n0\n', self.LINKS[0])
            self.assertIsNone(written)
            self.assertIn('только ссылки Snell версии 4/5', output)

    def test_v5_clear_http_and_api_errors_never_claim_success(self):
        for kwargs in (dict(put_exit=22), dict(put_exit=7), dict(put_response={'error': 'Fixture error'}),
                       dict(put_response={})):
            with self.subTest(kwargs=kwargs):
                written, output = self.edit_snell('2\n1\n3\ny\n0\n', **kwargs)
                self.assertEqual(written, {'snell_uri': '\n'.join(self.LINKS[::2])})
                self.assertIn('Ошибка сохранения', output)
                self.assertNotIn('успешно обновлены', output)
                self.assertNotIn('очищены!', output)

    def test_snell_choice_passes_current_user_to_new_implementation(self):
        output = self.render({}, '2\n2\n0\n')
        self.assertIn('Snell v6', output)
        self.assertIn('SNELL6:menu --user fixture-user', output)

    def test_snell_cancel_does_not_enter_link_editor(self):
        output = self.render({}, '2\n0\n0\n')
        self.assertIn('Snell v5', output)
        self.assertNotIn('Текущие ссылки', output)

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
