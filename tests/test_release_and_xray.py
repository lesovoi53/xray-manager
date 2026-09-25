import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assets = load('release-assets')
xray = load('xray-discovery')
ports = load('plan-ports')


class ReleaseAndXray(unittest.TestCase):
    def test_bad_hash_and_missing_asset_leave_destination_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root/'assets'; source.mkdir()
            (source/'component').write_bytes(b'new')
            destination = root/'working'; destination.write_bytes(b'old')
            manifest = dict(repository=assets.REPOSITORY, release='v2026.09.25.1', sha256={'component': '0'*64})
            with self.assertRaises(ValueError):
                assets.fetch(manifest, 'component', destination, source)
            self.assertEqual(destination.read_bytes(), b'old')
            manifest['sha256']['component'] = hashlib.sha256(b'new').hexdigest()
            assets.fetch(manifest, 'component', destination, source)
            self.assertEqual(destination.read_bytes(), b'new')
            (source/'component').unlink()
            with self.assertRaises(OSError):
                assets.fetch(manifest, 'component', destination, source)
            self.assertEqual(destination.read_bytes(), b'new')

    def test_standalone_discovery_and_repeat_preserve_nonstandard_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config = root/'etc/xray/config.json'; config.parent.mkdir(parents=True)
            inbounds = [dict(protocol='socks', listen='127.0.0.1', port=21081, settings={'auth':'noauth'}),
                        dict(protocol='dokodemo-door', listen='127.0.0.1', port=21082, settings={'followRedirect':True,'network':'tcp'}),
                        dict(protocol='dokodemo-door', listen='127.0.0.1', port=21083, settings={'followRedirect':True,'network':'tcp,udp'}, streamSettings={'sockopt':{'tproxy':'tproxy'}})]
            config.write_text('// comment\n'+json.dumps(dict(inbounds=inbounds)))
            original = config.read_bytes()
            with patch.dict('os.environ', {}, clear=True):
                first = ports.plan(root)
                second = ports.plan(root)
            self.assertEqual(first, second)
            self.assertEqual([first[k] for k in xray.KEYS], [21081,21082,21083])
            self.assertEqual(config.read_bytes(), original)

    def test_ambiguous_and_authenticated_gateways_are_not_silently_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'config.json'
            p.write_text(json.dumps(dict(inbounds=[dict(protocol='socks',listen='127.0.0.1',port=n,settings={}) for n in (21081,21082)])))
            with patch.dict('os.environ', {}, clear=True), self.assertRaises(ValueError):
                xray.discover([p])
            p.write_text(json.dumps(dict(inbounds=[dict(protocol='socks',listen='127.0.0.1',port=21081,settings={'auth':'password'})])))
            with patch.dict('os.environ', {}, clear=True):
                self.assertEqual(xray.discover([p]), {})

    def test_runtime_downloads_do_not_use_upstream_or_moving_main(self):
        for name in ('install.sh','bin/x-manager','scripts/update-release.sh'):
            text = (ROOT/name).read_text()
            for value in ('https://github.com/enfein/mieru', 'https://github.com/spkprsnts/webdav-tunnel', 'dl.nssurge.com', '/main/', 'codeload.github.com'):
                self.assertFalse(value in text, name + ' contains moving/upstream download ' + value)


if __name__ == '__main__':
    unittest.main()
