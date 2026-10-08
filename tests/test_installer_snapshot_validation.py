"""Refuse incomplete SQLite snapshots before restore can stop or modify anything."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('snapshot_validation', ROOT/'scripts/installer-state.py')
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)


class SnapshotValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backup = self.root/'backup'
        self.backup.mkdir()
        self.database = self.root/'panel.db'
        connection = sqlite3.connect(self.database)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('CREATE TABLE users (name TEXT)')
        connection.commit()
        connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        connection.execute('INSERT INTO users VALUES (?)', ('synthetic-user',))
        connection.commit()
        with tarfile.open(self.backup/'files.tar', 'w') as archive:
            archive.add(self.database, arcname=str(self.database).lstrip('/'))
        snapshot = sqlite3.connect(self.backup/'database-0.sqlite')
        connection.backup(snapshot)
        snapshot.close()
        connection.close()
        self.description = {'paths': [str(self.database)], 'services': {},
                            'databases': [{'path': str(self.database), 'backup': 'database-0.sqlite'}]}
        (self.backup/'state.json').write_text(json.dumps(self.description))
        (self.backup/'iptables').write_text('')

    def rejected_without_mutation(self):
        before = self.database.read_bytes()
        with patch.object(state, 'check_external_watchdog'), patch.object(state, 'SERVICES', []), \
                patch.object(state, 'save_watcher_policy', return_value=({}, {})), \
                patch.object(state, 'restore_watcher_policy'), \
                patch.object(state.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='')) as commands:
            with self.assertRaisesRegex(ValueError, 'SQLite snapshot'):
                state.restore(self.backup)
            commands.assert_not_called()
        self.assertEqual(self.database.read_bytes(), before)
        with closing(sqlite3.connect(self.database)) as database:
            self.assertEqual(database.execute('SELECT count(*) FROM users').fetchone()[0], 1)

    def test_missing_snapshot_refused_instead_of_silent_wal_user_loss(self):
        (self.backup/'database-0.sqlite').unlink()
        self.rejected_without_mutation()

    def test_corrupt_snapshot_refused_before_services_or_files_change(self):
        (self.backup/'database-0.sqlite').write_bytes(b'corrupt database')
        self.rejected_without_mutation()

    def test_zero_length_snapshot_is_not_an_empty_valid_database(self):
        (self.backup/'database-0.sqlite').write_bytes(b'')
        self.rejected_without_mutation()

    def test_valid_header_with_corrupt_database_pages_is_refused(self):
        snapshot = self.backup/'database-0.sqlite'
        content = bytearray(snapshot.read_bytes())
        content[100] = 255  # Impossible SQLite b-tree page type, header stays valid.
        snapshot.write_bytes(content)
        self.rejected_without_mutation()

    def test_unreadable_snapshot_is_refused(self):
        original_open = Path.open
        def unreadable(path, *args, **kwargs):
            if path == self.backup/'database-0.sqlite':
                raise PermissionError('synthetic read failure')
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', unreadable):
            self.rejected_without_mutation()

    def test_required_snapshot_must_stay_in_private_backup_directory(self):
        self.description['databases'][0]['backup'] = '../panel.db'
        (self.backup/'state.json').write_text(json.dumps(self.description))
        self.rejected_without_mutation()

    def test_valid_existing_backup_remains_compatible(self):
        self.assertEqual(state.validate_backup(self.backup), self.description)

    def test_valid_snapshot_restores_committed_wal_user(self):
        with patch.object(state, 'check_external_watchdog'), patch.object(state, 'SERVICES', []), \
                patch.object(state, 'save_watcher_policy', return_value=({}, {})), \
                patch.object(state, 'restore_watcher_policy'), \
                patch.object(state.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='')):
            state.restore(self.backup)
        with closing(sqlite3.connect(self.database)) as database:
            self.assertEqual(database.execute('SELECT count(*) FROM users').fetchone()[0], 1)

    def test_backup_without_databases_remains_compatible(self):
        self.description['databases'] = []
        (self.backup/'state.json').write_text(json.dumps(self.description))
        self.assertEqual(state.validate_backup(self.backup), self.description)

    def test_network_backup_rejects_unmanaged_keys_before_any_mutation(self):
        self.description['network_runtime'] = {'kernel.panic': '1'}
        (self.backup/'state.json').write_text(json.dumps(self.description))
        before = self.database.read_bytes()
        with patch.object(state, 'check_external_watchdog'), patch.object(state, 'run') as commands:
            with self.assertRaisesRegex(ValueError, 'Invalid network runtime backup'):
                state.restore(self.backup)
            commands.assert_not_called()
        self.assertEqual(self.database.read_bytes(), before)

    def test_network_restore_verifies_tcp_triples_and_fails_on_ineffective_write(self):
        values = {'net.ipv4.tcp_rmem': '4096 87380 4194304'}
        with patch.object(Path, 'read_text', side_effect=['4096\t87380\t8388608', values['net.ipv4.tcp_rmem']]), patch.object(state, 'run') as command:
            state.restore_network_runtime(values)
            command.assert_called_once_with('sysctl', '-w', 'net.ipv4.tcp_rmem=4096 87380 4194304', stdout=subprocess.DEVNULL)
        with patch.object(Path, 'read_text', return_value='4096 87380 8388608'), patch.object(state, 'run'):
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                state.restore_network_runtime(values)


if __name__ == '__main__':
    unittest.main()
