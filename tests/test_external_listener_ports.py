"""Existing external listener discovery is read-only and never guesses a port."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('external_listener_ports', ROOT/'scripts/external-listener-ports.py')
ports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ports)


def properties(arguments, **values):
    data = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0',
            'ExecStart': '{ path=/usr/local/bin/wdtt ; argv[]=/usr/local/bin/wdtt '+arguments+' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }'}
    data.update(values)
    return data


class ExternalListenerPorts(unittest.TestCase):
    def discover(self, values, root=Path('/')):
        response = subprocess.CompletedProcess([], 0, stdout='\n'.join(key+'='+value for key, value in values.items()))
        with patch.object(ports.subprocess, 'run', return_value=response) as command:
            port = ports.discover('wdtt.service', root)
        self.assertEqual(command.call_args.args[0][:3], ['systemctl', 'show', 'wdtt.service'])
        self.assertEqual(command.call_args.kwargs['timeout'], 15)
        return port

    def test_explicit_listener_formats(self):
        for argument in ('-listen 0.0.0.0:56000', '--listen :56000', '-listen=127.0.0.1:56000',
                         '--listen=[::]:56000', '--listen "[::1]:56000"', '--listen localhost:56000'):
            with self.subTest(argument=argument):
                self.assertEqual(self.discover(properties(argument)), 56000)

    def test_environment_braced_standalone_and_composite_arguments(self):
        for argument, environment in [('-listen ${BIND}', 'BIND=0.0.0.0:56000'),
                                      ('-listen $BIND', 'BIND=:56000'),
                                      ('--listen=0.0.0.0:${PORT}', 'PORT=56000'),
                                      ('$FLAGS', '"FLAGS=--listen :56000"')]:
            with self.subTest(argument=argument):
                self.assertEqual(self.discover(properties(argument, Environment=environment)), 56000)

    def test_environmentfile_overrides_environment_without_shell_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root/'etc/wdtt.env'
            file.parent.mkdir()
            file.write_text('# comment\nBIND="[::]:56000"\nPASSWORD=$(touch /tmp/never-run)\n')
            before = file.read_bytes()
            self.assertEqual(self.discover(properties('--listen ${BIND}', Environment='BIND=:1234',
                             EnvironmentFiles='/etc/missing.env (ignore_errors=yes) /etc/wdtt.env (ignore_errors=no)'), root), 56000)
            self.assertEqual(file.read_bytes(), before)

    def test_running_service_uses_actual_process_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cmdline = root/'proc/321/cmdline'
            cmdline.parent.mkdir(parents=True)
            cmdline.write_bytes(b'/usr/local/bin/wdtt\x00-listen\x000.0.0.0:56000\x00')
            self.assertEqual(self.discover(properties('-listen :11111', ActiveState='active', MainPID='321'), root), 56000)

    def test_absent_and_masked_services_do_not_get_default_ports(self):
        for load in ('not-found', 'masked'):
            self.assertIsNone(self.discover({'LoadState': load}))

    def test_ambiguous_missing_or_false_positive_options_are_rejected(self):
        for argument in ('', '--web-listen :56000', '--description "-listen :56000"',
                         '-- --listen :56000', '--listen :56000 --listen :56000',
                         '--listen :1234 -listen :56000', '-listen', '--listen='):
            with self.subTest(argument=argument), self.assertRaises(ValueError):
                self.discover(properties(argument))

    def test_invalid_address_or_port_never_reaches_firewall(self):
        for address in (':0', ':65536', ':abc', '::1:56000', '[bad]:56000',
                        '0.0.0.0:56000/something', '$(echo:56000)', '0.0.0.0:56000;'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.discover(properties('--listen '+address))

    def test_unresolved_unset_and_required_environment_files_fail_closed(self):
        for extra in ({}, {'Environment': 'BIND=:56000', 'UnsetEnvironment': 'BIND'},
                      {'EnvironmentFiles': '/not-present/wdtt-env (ignore_errors=no)'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.discover(properties('--listen ${BIND}', **extra))

    def test_multiple_commands_or_shell_wrappers_are_not_parsed_as_listener(self):
        original = properties('-listen :56000')['ExecStart']
        for command in (original+' '+original, original.replace('/usr/local/bin/wdtt', '/bin/sh')):
            with self.assertRaises(ValueError):
                self.discover(properties('', ExecStart=command))

    def test_transition_and_systemd_failure_are_explicit(self):
        with self.assertRaisesRegex(ValueError, 'stable'):
            self.discover(properties('-listen :56000', ActiveState='activating'))
        with patch.object(ports.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stdout='')):
            with self.assertRaisesRegex(ValueError, 'Cannot inspect'):
                ports.discover('wdtt.service')

    def test_actual_installer_rejects_ambiguous_listener_before_transaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'scripts').mkdir()
            shutil.copyfile(ROOT/'install.sh', root/'install.sh')
            shutil.copyfile(ROOT/'scripts/external-listener-ports.py', root/'scripts/external-listener-ports.py')
            # Only OS/dependency endpoints are substituted; run the real installer
            # until it must abort at listener preflight, before xm_begin.
            (root/'scripts/installer-common.sh').write_text('''xm_preflight() { :; }
xm_check_external_watchdog() { :; }
xm_die() { echo "$*" >&2; exit 1; }
xm_begin() { touch "$FIXTURE/transaction-started"; exit 99; }
''')
            fake = root/'bin'
            fake.mkdir()
            for name in ('apt-get', 'curl', 'wget', 'jq', 'unzip', 'iptables', 'iptables-save', 'iptables-restore', 'openssl', 'ip', 'runuser', 'clear'):
                command = fake/name
                command.write_text('#!/bin/sh\nexit 0\n')
                command.chmod(0o755)
            command = fake/'systemctl'
            response = '\n'.join(key+'='+value for key, value in properties('-listen :56000 --listen :56001').items())
            command.write_text('#!/bin/sh\n[ "$1" = show ] || exit 3\ncat <<\'RESPONSE\'\n'+response+'\nRESPONSE\n')
            command.chmod(0o755)
            result = subprocess.run(['bash', str(root/'install.sh'), '--update'], text=True, capture_output=True,
                                    env=dict(os.environ, FIXTURE=str(root), PATH=str(fake)+':'+os.environ['PATH']))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('External listener preflight failed', result.stderr)
            self.assertFalse((root/'transaction-started').exists())


if __name__ == '__main__':
    unittest.main()
