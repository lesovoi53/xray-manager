import contextlib, importlib.util, io, unittest
from pathlib import Path
from unittest.mock import Mock, patch
ROOT=Path(__file__).resolve().parents[1]
def load(name):
 s=importlib.util.spec_from_file_location(name,ROOT/'scripts'/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class Presentation(unittest.TestCase):
 def test_openflux_has_one_entry_and_does_not_mutate(self):
  m=load('tuna-watchdog');controller=Mock();controller.conflicts.return_value=[]
  group=Mock();group.status.return_value=dict(configured=True,attempts=3,spent=2,remaining=1,delay=10)
  output=io.StringIO()
  with patch.object(m,'UNITS',['openflux@'+str(i) for i in range(1,9)]),patch.object(m,'lifecycle',return_value=controller),patch.object(m,'openflux_watchdog',return_value=group),patch.object(m,'show',return_value=dict(LoadState='loaded',ActiveState='active')),patch('builtins.input',return_value='0'),contextlib.redirect_stdout(output):m.menu()
  text=output.getvalue();self.assertEqual(text.count('[1] OpenFlux:'),1);self.assertNotIn('openflux@',text);self.assertIn('осталось 1',text);group.configure.assert_not_called();group.reset.assert_not_called()
 def test_health_fields_have_separate_lines(self):
  m=load('watchdog-health');output=io.StringIO()
  result=dict(config=dict(units={'x-ui.service':dict(kind='xray',failures=2,max_restarts=3,cooldown=30)}),counters=dict(units={}),timer=dict(ActiveState='active'),conflicting_watchdogs=[])
  with contextlib.redirect_stdout(output):m.human_result(result)
  lines=output.getvalue().splitlines()
  for label in ('Служба:','  Проверка:','  Ошибок подряд','  Пауза','  Лимит','  Использовано','  Осталось'):self.assertEqual(sum(line.startswith(label) for line in lines),1)
 def test_conflicts_human_empty_active_and_json_compatibility(self):
  m=load('service-control')
  for rows,expected in (([], 'Конфликтов watchdog нет.'), ([dict(unit='vpn-watchdog.service',conflict=True)], 'Внешний VPN Watchdog')):
   output=io.StringIO()
   with patch.object(m.Controller,'conflicts',return_value=rows),patch('sys.argv',['service-control.py','conflicts','--human']),contextlib.redirect_stdout(output):
    self.assertEqual(m.main(),0)
   self.assertIn(expected,output.getvalue());self.assertNotIn('[]',output.getvalue())
  output=io.StringIO()
  with patch.object(m.Controller,'conflicts',return_value=[]),patch('sys.argv',['service-control.py','conflicts']),contextlib.redirect_stdout(output):m.main()
  self.assertEqual(output.getvalue().strip(),'[]')
if __name__=='__main__':unittest.main()
