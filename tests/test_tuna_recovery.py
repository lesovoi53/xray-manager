import importlib.util
from pathlib import Path
import tempfile
import unittest
from contextlib import nullcontext
from types import SimpleNamespace

spec=importlib.util.spec_from_file_location('recovery',Path(__file__).resolve().parents[1]/'scripts/tuna-recovery.py')
recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.now=1000;self.commands=[];self.allowed=True;self.conflict=False
        self.live={'LoadState':'loaded','ActiveState':'failed','Result':'start-limit-hit','UnitFileState':'enabled'}
        controller=SimpleNamespace(lock=nullcontext,allowed=lambda u:self.allowed,conflicts=lambda:[{'conflict':self.conflict}])
        self.watch=SimpleNamespace(UNITS=['mita'],lifecycle=lambda:controller,show=lambda u:self.live,ctl=lambda *args:self.commands.append(args))
        self.tool=recovery.Recovery(self.root,self.watch,lambda:self.now)
        self.policy=self.root/'etc/systemd/system/mita.service.d/90-tuna-watchdog.conf'
        self.policy.parent.mkdir(parents=True)
        self.policy.write_text(recovery.HEADER+'[Unit]\nStartLimitIntervalSec=infinity\nStartLimitBurst=6\n[Service]\nRestart=on-failure\nRestartSec=5s\n')

    def test_modified_policy_is_not_adopted_and_nonfinite_state_is_rejected(self):
        self.policy.write_text(self.policy.read_text()+'ExecStart=/custom/admin-service\n')
        self.tool.tick();self.now+=600;self.tool.tick()
        self.assertEqual(self.commands, [])
        self.tool.path(recovery.STATE).write_text('{"mita":NaN}')
        with self.assertRaises(ValueError): self.tool.tick()

    def test_recovery_without_any_external_watchdog(self):
        self.watch.lifecycle().conflicts = lambda: []
        self.tool.tick()
        self.now += 300
        self.tool.tick()
        self.assertEqual(self.commands, [('reset-failed', 'mita'), ('start', '--no-block', 'mita')])

    def test_restart_only_after_300_seconds_and_persistent_across_processes(self):
        self.tool.tick();self.now+=299;self.tool.tick();self.assertEqual(self.commands,[])
        self.now+=1
        recovery.Recovery(self.root,self.watch,lambda:self.now).tick()
        self.assertEqual(self.commands,[('reset-failed','mita'),('start','--no-block','mita')])
        self.tool.tick();self.assertEqual(len(self.commands),2)

    def test_manual_stop_off_mask_and_unmanaged_never_restart(self):
        for state in ('inactive','active','deactivating'):
            self.live['ActiveState']=state;self.tool.tick();self.now+=600;self.tool.tick()
        self.live['ActiveState']='failed';self.allowed=False;self.tool.tick();self.now+=600;self.tool.tick()
        self.allowed=True;self.live['UnitFileState']='masked';self.tool.tick()
        self.live['UnitFileState']='enabled';self.policy.write_text('[Service]\nRestart=on-failure\n')
        self.tool.tick();self.assertEqual(self.commands,[])

    def test_conflicting_watchdog_and_disabled_policy(self):
        self.conflict=True;self.tool.tick();self.assertFalse(self.tool.path(recovery.STATE).exists())
        self.conflict=False;self.policy.write_text(recovery.HEADER+'Restart=no\n')
        self.tool.tick();self.now+=600;self.tool.tick();self.assertEqual(self.commands,[])

    def test_stop_cancels_pending_recovery(self):
        self.tool.tick();self.now+=301;self.allowed=False;self.tool.tick()
        self.allowed=True;self.live['ActiveState']='inactive';self.tool.tick()
        self.assertEqual(self.commands,[])

    def test_normal_failure_does_not_compete_with_systemd_restarts(self):
        self.live['Result']='exit-code';self.tool.tick();self.now+=600;self.tool.tick()
        self.assertEqual(self.commands,[])

    def test_debian13_preserves_exit_code_after_start_limit(self):
        self.live.update(Result='exit-code', NRestarts='6', StartLimitBurst='6',
                         Restart='on-failure', StartLimitIntervalUSec='infinity')
        self.tool.tick();self.now+=300;self.tool.tick()
        self.assertEqual(self.commands,[('reset-failed','mita'),('start','--no-block','mita')])

    def test_failed_service_below_burst_is_not_exhausted(self):
        self.live.update(Result='exit-code', NRestarts='5', StartLimitBurst='6',
                         Restart='on-failure', StartLimitIntervalUSec='infinity')
        self.tool.tick();self.now+=600;self.tool.tick()
        self.assertEqual(self.commands,[])


if __name__=='__main__':unittest.main()
