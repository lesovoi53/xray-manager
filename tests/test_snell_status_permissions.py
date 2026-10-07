"""Regression for subscription-reader permissions and both Snell menu screens."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SnellStatusPermissions(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'requires Linux root to drop privileges')
    def test_upgrade_and_repeated_writes_allow_subscription_reader_only_stat(self):
        control = load(Path(os.environ.get('XM_CONTROL_UNDER_TEST', ROOT/'scripts/service-control.py')))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            calls = []
            ctl = control.Controller(root, lambda *args: calls.append(args) or '')
            old_umask = os.umask(0o077)
            try:
                # Simulate the previous release, including a stopped marker which
                # reconcile does not rewrite. Empty intent avoids systemd changes.
                for folder in (control.STATE_DIR, control.STATE_DIR+'/off', control.RUNTIME_DIR, control.RUNTIME_DIR+'/stopped'):
                    ctl.path(folder).mkdir(parents=True, exist_ok=True)
                    ctl.path(folder).chmod(0o700)
                for folder in ('etc', 'etc/x-manager', 'run', 'run/x-manager'):
                    (root/folder).chmod(0o755)
                original = '{"version":1,"units":{}}\n'
                ctl.state_path.write_text(original)
                marker = ctl.markers('snell6@1.service')[1]
                marker.write_text('manual stop\n')
                ctl.reconcile()
                self.assertEqual(ctl.state_path.read_text(), original)
                self.assertEqual(marker.read_text(), 'manual stop\n')
                self.assertEqual(calls, [])
                # Subsequent operations must not undo the migration.
                with ctl.lock():
                    ctl.save({'version': 1, 'units': {}})
                    for path in ctl.markers('snell.service'):
                        control.atomic_write(path, 'off\n')
                selection = root/'selection.json'
                selection.write_text(json.dumps(dict(format=1, version=6, slot='1', unit='snell6@1.service', endpoint_id='a'*32)))
                selection.chmod(0o644)
                tree = ast.parse((ROOT/'tuna-sub-server/tuna-subscriptions.py').read_text())
                nodes = [n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ('SnellSelectionError','snell_delivery_selection')]
                probe = 'import os,re,json,sqlite3\n'+ast.unparse(ast.Module(body=nodes,type_ignores=[]))+'\n'
                probe += 'SNELL_SELECTION_FILE='+repr(str(selection))+'\n'
                probe += 'SNELL_SERVICE_CONTROL_DIRS='+repr(tuple(str(ctl.path(d)) for d in (control.STATE_DIR+'/off',control.RUNTIME_DIR+'/stopped')))+'\n'
                probe += 'result=snell_delivery_selection(sqlite3.connect(":memory:"),"test")\nassert json.loads(result[2])["service_control_disabled"] is True\n'
                probe += 'try:\n open('+repr(str(ctl.state_path))+').read()\nexcept PermissionError:\n print("PASS private state")\nelse:\n raise AssertionError("private state readable")\n'
                def drop():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)
                result = subprocess.run(['python3','-B','-'],input=probe,text=True,capture_output=True,preexec_fn=drop,timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('PASS private state',result.stdout)
            finally:
                os.umask(old_umask)

    def test_both_menus_show_v6_status_and_leave_services_untouched(self):
        script = r'''
source "$1"
xm_header() { :; }
get_snell_status() { echo ОСТАНОВЛЕН; }
for name in mieru wdavtunnel openflux dns wdtt csqtt; do eval "get_${name}_status() { echo OTHER; }"; done
python3() { [[ "$2 $3" == 'status --human' ]] || return 99; echo РАБОТАЕТ; }
systemctl() { echo UNEXPECTED_MUTATION; return 99; }
xm_snell_menu <<< 0
xm_services_menu <<< 0
'''
        p = subprocess.run(['bash','-c',script,'bash',str(ROOT/'scripts/menu-v2.sh')],text=True,capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('[2] Snell v6   РАБОТАЕТ',p.stdout)
        self.assertIn('v5: ОСТАНОВЛЕН | v6: РАБОТАЕТ',p.stdout)
        self.assertNotIn('UNEXPECTED_MUTATION',p.stdout)

    def test_status_labels_cover_missing_failed_and_conflicting_services(self):
        tree = ast.parse((ROOT/'scripts/snell6-endpoints.py').read_text())
        nodes = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('state_label','status_summary')]
        ns={}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'status','exec'),ns)
        for states,label in (([], 'НЕ НАСТРОЕН'),(['active'],'РАБОТАЕТ'),(['inactive'],'ОСТАНОВЛЕН'),(['failed'],'ОШИБКА'),(['activating'],'ЗАПУСКАЕТСЯ'),(['unknown'],'СТАТУС НЕИЗВЕСТЕН'),(['inactive','active'],'РАБОТАЕТ')):
            self.assertEqual(ns['status_summary']([{'ActiveState':v} for v in states]),label)
        self.assertTrue(ns['status_summary']([{'ActiveState':'active'}]*2).startswith('ОШИБКА:'))
