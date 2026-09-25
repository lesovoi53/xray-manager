from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MenuNavigation(unittest.TestCase):
    def test_every_catalog_menu_can_go_back_without_an_action(self):
        names = {line.split('|')[0] for line in (ROOT/'scripts/menu-actions.tsv').read_text().splitlines()}
        for name in names:
            script = '. "$1"; xm_header() { :; }; get_mieru_status() { echo active; }; get_snell_status() { echo active; }; get_openflux_status() { echo active; }; get_openflux_pool_mode_label() { echo classic; }; get_wdavtunnel_status() { echo active; }; get_wdavtunnel_provider_label() { echo selfhosted; }; get_sub_server_status() { echo active; }; xm_choose_action "$2" selected; test "$selected" = 0'
            result = subprocess.run(['bash','-c',script,'bash',str(ROOT/'scripts/menu-v2.sh'),name],input='0\n',text=True,capture_output=True,timeout=5)
            self.assertEqual(result.returncode, 0, name+': '+result.stderr)

    def test_update_maps_to_existing_checked_updater(self):
        script = '. "$1"; xm_header() { :; }; get_mieru_status() { echo active; }; xm_choose_action menu_mieru selected; test "$selected" = 11'
        result = subprocess.run(['bash','-c',script,'bash',str(ROOT/'scripts/menu-v2.sh')],input='3\n4\n',text=True,capture_output=True,timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Обновить полный выпуск', result.stdout)

    def test_opening_subscription_menu_no_longer_replaces_daemon(self):
        source = (ROOT/'bin/x-manager').read_text()
        self.assertNotIn('sync_tuna_sub_daemon', source)
        start = source.index('menu_subscriptions() {')
        header = source[start:source.index('    while true;',start)]
        self.assertNotIn('sync_openflux_to_sub_server', header)


if __name__ == '__main__':
    unittest.main()
