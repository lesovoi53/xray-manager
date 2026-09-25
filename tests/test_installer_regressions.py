"""Run on Linux: python3 -m unittest discover -s tests -v.

Source real shell functions without running the interactive menu or installer.
All credentials are synthetic; assertions never print them.
"""
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def function(name):
    source = (ROOT / "bin/x-manager").read_text()
    match = re.search(r"^" + name + r"\(\) \{\n.*?(?=^[A-Za-z_]\w*\(\) \{|\Z)", source, re.M | re.S)
    if not match:
        raise AssertionError("Shell function missing: " + name)
    return match.group()


class InstallerRegressions(unittest.TestCase):
    def test_webdav_legacy_credentials_match_runner(self):
        script = function("get_wdavtunnel_listen_port") + '\n' + function("test_all_webdav_accounts") + r'''
get_wdavtunnel_prop() {
    case "$1" in
        WEBDAV_PASSWORD) printf '%s' 'fixture-password';;
        *) printf '%s' "$2";;
    esac
}
test_webdav_account() {
    if [ "$1" = selfhosted ]; then
        [ "$2" = wdav ] && [ "$3" = fixture-password ] || exit 91
    fi
}
test_all_webdav_accounts >/dev/null
'''
        result = subprocess.run(["bash", "-c", script], capture_output=True)
        self.assertEqual(result.returncode, 0, "Legacy credentials differ from runner")

    def test_catalog_accepts_current_and_legacy_responses(self):
        for response in ('{"success":true,"imported_count":7}', '{"status":"ok","count":7}'):
            script = function("menu_openflux_sub_catalog") + r'''
clear() { :; }
curl() {
    case "$*" in *import-local*) printf '%s' "$RESPONSE";; *) printf '%s' '{"groups":[]}' ;; esac
}
menu_openflux_sub_catalog
'''
            import os
            result = subprocess.run(["bash", "-c", script], input="1\n\n0\n", text=True,
                                    capture_output=True, env=dict(os.environ, RESPONSE=response), timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Импортировано/синхронизировано групп: 7", result.stdout)
            self.assertNotIn("Ошибка импорта", result.stdout)

    def test_mita_links_do_not_form_cycle(self):
        source = (ROOT / "install.sh").read_text()
        start = source.index('    ln -sf /usr/bin/mita') if '    ln -sf /usr/bin/mita' in source else -1
        if start < 0:
            # Regression is exercised by full installation tests after this obsolete block is removed.
            return
        block = source[start:source.index('    echo ', start)]
        with tempfile.TemporaryDirectory() as tmp:
            for path in ("usr/bin", "usr/local/bin"):
                pathlib.Path(tmp, path).mkdir(parents=True, exist_ok=True)
            binary = pathlib.Path(tmp, "usr/bin/mita")
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            result = subprocess.run(["bash", "-c", block.replace("/usr/", tmp + "/usr/")])
            self.assertEqual(result.returncode, 0)
            self.assertTrue(binary.is_file(), "Installer replaced the Mieru binary with a symlink cycle")


if __name__ == "__main__":
    unittest.main()
