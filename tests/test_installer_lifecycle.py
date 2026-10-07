"""Real shell policy functions with synthetic systemd command boundary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class InstallerLifecycle(unittest.TestCase):
    def exercise(self,operation,previous,policy=0):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);(base/'scripts').mkdir();(base/'backup').mkdir()
            (base/'backup/state.json').write_text(json.dumps({'services':{'snell.service':previous}}))
            (base/'scripts/service-control.py').write_text('raise SystemExit('+str(policy)+')\n')
            script=r'''
set -e
source "$COMMON"
SCRIPT_DIR="$FIXTURE"
XM_BACKUP="$FIXTURE/backup"
systemctl() { printf '%s\n' "$*" >> "$FIXTURE/commands"; }
sleep() { :; }
"$OPERATION" snell
'''
            result=subprocess.run(['bash','-c',script],env=dict(os.environ,COMMON=str(ROOT/'scripts/installer-common.sh'),FIXTURE=d,OPERATION=operation),text=True,capture_output=True)
            commands=(base/'commands').read_text() if (base/'commands').exists() else ''
            return result,commands

    def test_update_never_reenables_existing_units(self):
        for mode in ('disabled','masked','masked-runtime','static','enabled','enabled-runtime'):
            with self.subTest(mode=mode):
                result,commands=self.exercise('xm_enable',{'enabled':mode,'active':False})
                self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(commands,'')

    def test_clean_install_enables_new_unit(self):
        result,commands=self.exercise('xm_enable',{'enabled':'not-found','active':False})
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('enable snell',commands)

    def test_update_keeps_stopped_enabled_and_disabled(self):
        for mode in ('disabled','enabled','masked'):
            result,commands=self.exercise('xm_service',{'enabled':mode,'active':False})
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(commands,'')

    def test_update_restarts_previously_running_service(self):
        result,commands=self.exercise('xm_service',{'enabled':'enabled','active':True})
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('restart snell',commands)

    def test_inhibit_wins_over_previous_active_state(self):
        result,commands=self.exercise('xm_service',{'enabled':'enabled','active':True},policy=1)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(commands,'')

    def test_policy_failure_is_fatal_not_permission_to_start(self):
        result,commands=self.exercise('xm_service',{'enabled':'enabled','active':True},policy=2)
        self.assertNotEqual(result.returncode,0);self.assertEqual(commands,'')

if __name__=='__main__':unittest.main()
