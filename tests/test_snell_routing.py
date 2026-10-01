import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
r=load('snell-routing');installer=load('installer-state')


class Routing(unittest.TestCase):
    def test_gateway_mismatch_rejected_before_listener_check(self):
        cfg=dict(inbounds=[dict(tag='red',listen='127.0.0.1',port=12346,protocol='dokodemo-door',settings=dict(network='tcp',followRedirect=True)),
                           dict(tag='tp',listen='127.0.0.1',port=12345,protocol='dokodemo-door',settings=dict(network='tcp,udp',followRedirect=True),streamSettings=dict(sockopt=dict(tproxy='tproxy')))])
        different=copy.deepcopy(cfg);different['routing']=dict(rules=[dict(inboundTag=['red'],outboundTag='vpn')])
        missing_udp=copy.deepcopy(cfg);missing_udp['inbounds'][1]['settings']['network']='tcp'
        missing_transparent=copy.deepcopy(cfg);missing_transparent['inbounds'][1]['streamSettings']={}
        for invalid in (different,missing_udp,missing_transparent,{'inbounds':[]}):
            with self.assertRaises(r.Error),patch.object(Path,'read_text',side_effect=AssertionError('Must preflight first')):
                r.verify_gateways([invalid],12346,12345,988)
        with patch.object(Path,'read_text',return_value='header\n'):
            with self.assertRaisesRegex(r.Error,'listener missing'):r.verify_gateways([cfg],12346,12345,988)

    def test_reply_exclusions_and_udp_not_established_bypass(self):
        rules=r.build_rules('*mangle\nCOMMIT\n','mangle','xray',988,1488,[],12346,12345)
        self.assertIn('--ctdir REPLY',rules)
        self.assertIn('-p udp --sport 1488 -j RETURN',rules)
        self.assertIn('-i lo -p udp -m mark',rules)
        self.assertNotIn('ESTABLISHED',rules)
        self.assertNotIn('REDIRECT',rules)

    def test_mode_is_not_saved_on_failure_and_backup_keeps_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'routing.mode';path.write_text('direct\n');path.chmod(0o640)
            def failure(mode):raise r.Error('Gateway invalid')
            with self.assertRaises(r.Error):r.change_mode(path,'xray',failure)
            self.assertEqual(path.read_text(),'direct\n')
            backup=root/'backup';backup.mkdir()
            r.change_mode(path,'xray',lambda mode:backup)
            self.assertEqual(path.read_text(),'xray\n')
            self.assertEqual(path.stat().st_mode&0o777,0o640)
            self.assertEqual((backup/'routing.mode.before').read_text(),'direct\n')

    def test_installer_restores_only_managed_policy_slot(self):
        empty=dict(rules=[],routes=[],owned=False)
        active=dict(rules=[dict(priority=1988,fwmark='0x534e',table=1988,src='all')],
                    routes=[dict(table=1988,type='local',dev='lo',dst='default')],owned=True)
        with patch.object(installer,'run') as run:
            installer.restore_snell_policy(empty,active)
            self.assertEqual(run.call_count,2)
            self.assertTrue(all('del' in c.args for c in run.call_args_list))
        with patch.object(installer,'run') as run:
            installer.restore_snell_policy(active,empty)
            self.assertEqual(run.call_count,2)
            self.assertTrue(all('add' in c.args for c in run.call_args_list))
        with patch.object(installer,'run') as run:
            installer.restore_snell_policy(active,active)
            run.assert_not_called()
        with patch.object(installer,'run') as run:
            with self.assertRaises(RuntimeError):installer.restore_snell_policy(empty,dict(active,owned=False))
            run.assert_not_called()


if __name__=='__main__':unittest.main()
