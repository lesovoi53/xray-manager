import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock

spec=importlib.util.spec_from_file_location('restore_qa',Path(__file__).resolve().parents[1]/'scripts/installer-state.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class RestoreReadiness(unittest.TestCase):
    def paths(self, udp_rows):
        values=iter(udp_rows)
        def read(path,*args,**kwargs):
            return {'/etc/snell/routing.mode':'xray','/etc/x-manager/gateways.env':'XRAY_REDIRECT_PORT=12346\nXRAY_TPROXY_PORT=12345\n'}.get(path.as_posix()) or next(values)
        return read

    def test_waits_for_udp_then_tcp_before_starting_dependent(self):
        with patch.object(mod.Path,'exists',return_value=True), patch.object(mod.Path,'read_text',self.paths(['header\n','header\n0: 0100007F:3039\n'])), patch.object(mod.time,'sleep') as sleep, patch.object(mod.socket,'create_connection',return_value=MagicMock()) as connect:
            mod.wait_snell_gateways()
            sleep.assert_called_once_with(.25)
            connect.assert_called_once_with(('127.0.0.1',12346),timeout=.5)

    def test_unavailable_gateway_times_out_without_start_command(self):
        with patch.object(mod.Path,'exists',return_value=True), patch.object(mod.Path,'read_text',self.paths(['header\n'])), patch.object(mod.time,'monotonic',side_effect=[0,31]), patch.object(mod.socket,'create_connection') as connect:
            with self.assertRaisesRegex(RuntimeError,'left stopped'):mod.wait_snell_gateways()
            connect.assert_not_called()

    def test_direct_route_does_not_wait_for_xray(self):
        with patch.object(mod.Path,'exists',return_value=True),patch.object(mod.Path,'read_text',return_value='direct'),patch.object(mod.socket,'create_connection') as connect:
            mod.wait_snell_gateways();connect.assert_not_called()

if __name__=='__main__':unittest.main()
