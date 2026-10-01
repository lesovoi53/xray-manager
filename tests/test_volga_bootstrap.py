import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('volga_bootstrap',REPO/'scripts/openflux-volga.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'instances').mkdir();(self.root/'profiles/multistream').mkdir(parents=True)
        (self.root/'pool.mode').write_text('multistream')
        (self.root/'instances/1.env').write_text('URL=""\nTRANSPORT="mailru"\nCODEC="batched"\nENCRYPTION_KEY="fixture"\n')
        self.source=self.root/'input';self.source.write_text('https://disk.yandex.ru/i/fixture')
        # Map the current hardcoded path too, so the original implementation
        # exercises real configure()/refresh() in an isolated directory.
        real_path=Path
        def mapped(p):return self.root if str(p)=='/etc/openflux' else self.root/'instances' if str(p)=='/etc/openflux/instances' else real_path(p)
        for mocker in [patch.object(v,'ROOT',self.root,create=True),patch.object(v,'Path',side_effect=mapped),
                       patch.object(v,'COOKIE',self.root/'cookies.txt'),patch.object(v.grp,'getgrnam',return_value=type('Group',(),{'gr_gid':os.getgid()})())]:
            mocker.start();self.addCleanup(mocker.stop)

    def failed_setup(self):
        with patch.object(v,'preflight',side_effect=ValueError('SmartCaptcha')),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):v.configure('1',self.source)

    def test_failed_auth_retains_private_draft_without_changing_channel(self):
        before=(self.root/'instances/1.env').read_bytes()
        self.failed_setup()
        draft=self.root/'volga-drafts/multistream/1.urls'
        self.assertTrue(draft.is_file(),'Failed authentication must retain a resumable draft')
        self.assertEqual(draft.read_text(),self.source.read_text())
        self.assertEqual(draft.stat().st_mode&0o777,0o640)
        self.assertEqual(draft.parent.stat().st_mode&0o777,0o750)
        self.assertEqual((self.root/'instances/1.env').read_bytes(),before)

    def test_refresh_reaches_yandex_with_draft_when_no_channel_exists(self):
        self.failed_setup()
        opener=type('Opener',(),{'open':lambda *_args,**_kwargs: (_ for _ in ()).throw(RuntimeError('fixture-network-reached'))})()
        with patch.object(v.urllib.request,'build_opener',return_value=opener):
            with self.assertRaisesRegex(RuntimeError,'fixture-network-reached'):v.refresh()

    def test_refresh_without_input_is_actionable(self):
        with self.assertRaisesRegex(ValueError,'Сначала введите ссылки'):v.refresh()

    def test_modes_are_isolated_and_discard_keeps_live_channel(self):
        self.failed_setup()
        (self.root/'pool.mode').write_text('classic')
        with self.assertRaisesRegex(ValueError,'нет черновика'):v.resume('1')
        v.discard('1')
        self.assertTrue((self.root/'volga-drafts/multistream/1.urls').exists())
        (self.root/'pool.mode').write_text('multistream')
        before=(self.root/'instances/1.env').read_bytes()
        v.discard('1');self.assertEqual((self.root/'instances/1.env').read_bytes(),before)
        self.assertFalse((self.root/'volga-drafts/multistream/1.urls').exists())

    def test_invalid_input_never_saved(self):
        self.source.write_text('https://example.org/not-yandex')
        with self.assertRaises(ValueError):v.configure('1',self.source)
        self.assertFalse((self.root/'volga-drafts').exists())

    def test_windows_command_is_one_line_and_download_failure_is_fatal(self):
        command=v.windows_command('192.0.2.89','49283')
        self.assertNotIn('\n',command)
        self.assertIn("Join-Path $env:USERPROFILE 'VolgaCookies'",command)
        self.assertIn('-P 49283',command)
        self.assertLess(command.index('if ($LASTEXITCODE -ne 0)'),command.index('& powershell.exe'))
        for host in ["host'; bad",'host name','$(bad)']:
            with self.assertRaises(ValueError):v.windows_command(host,'22')

    def test_active_channels_take_priority_over_abandoned_drafts(self):
        self.failed_setup()
        active='https://disk.yandex.ru/i/active'
        (self.root/'instances/2.env').write_text(f'TRANSPORT="vyandex"\nURL="{active}"\n')
        requested=[]
        def opened(request,**kw):
            requested.append(request.full_url);raise RuntimeError('fixture-network-reached')
        opener=type('Opener',(),{})();opener.open=opened
        with patch.object(v.urllib.request,'build_opener',return_value=opener):
            with self.assertRaises(RuntimeError):v.refresh()
        self.assertEqual(requested,[active])

    def test_captcha_during_refresh_keeps_cookies_and_draft(self):
        self.failed_setup()
        cookie=self.root/'cookies.txt'
        cookie.write_text('# Netscape HTTP Cookie File\n.yandex.ru\tTRUE\t/\tTRUE\t0\tsession\tfixture\n')
        original=cookie.read_bytes()
        response=type('Response',(),{'read':lambda *_:b'captcha','url':'https://disk.yandex.ru/showcaptcha'})()
        opener=type('Opener',(),{'open':lambda *_args,**_kw:contextlib.nullcontext(response)})()
        with patch.object(v.urllib.request,'build_opener',return_value=opener):
            with self.assertRaisesRegex(ValueError,'SmartCaptcha'):v.refresh()
        self.assertEqual(cookie.read_bytes(),original)
        self.assertTrue((self.root/'volga-drafts/multistream/1.urls').exists())

    def test_checker_captcha_explained_and_other_error_retained_privately(self):
        fake=self.root/'checker'
        fake.write_text('#!/bin/sh\necho "Document 1: auth: Volga requires interactive SmartCaptcha" >&2\nexit 1\n');fake.chmod(0o700)
        with self.assertRaisesRegex(ValueError,'ручную SmartCaptcha'):v.check_document([str(fake)],2)
        fake.write_text('#!/bin/sh\necho "fixture network error" >&2\nexit 3\n')
        with self.assertRaisesRegex(ValueError,'кодом 3'):v.check_document([str(fake)],2)
        report=self.root/'volga-check-error.txt'
        self.assertIn('fixture network error',report.read_text());self.assertEqual(report.stat().st_mode&0o777,0o600)

    def configure_with_service(self,fail=False):
        real_mkdtemp=tempfile.mkdtemp
        def mkdtemp(**kw):kw['dir']=self.root;return real_mkdtemp(**kw)
        def run(cmd,**kw):
            if cmd[1] in ('is-active','is-enabled'):return subprocess.CompletedProcess(cmd,0 if kw.get('check') else 3)
            if cmd[1]=='restart' and fail:raise subprocess.CalledProcessError(1,cmd)
            return subprocess.CompletedProcess(cmd,0)
        with patch.object(v,'preflight'),patch.object(v.tempfile,'mkdtemp',side_effect=mkdtemp),patch.object(v.time,'sleep'),\
             patch.object(v.subprocess,'run',side_effect=run),patch.object(v.subprocess,'check_output',return_value=b'123\n'),contextlib.redirect_stdout(io.StringIO()):
            v.resume('1')

    def test_resume_success_preserves_codec_key_and_removes_draft(self):
        self.failed_setup();self.configure_with_service()
        text=(self.root/'instances/1.env').read_text()
        self.assertIn('CODEC="batched"',text);self.assertIn('ENCRYPTION_KEY="fixture"',text)
        self.assertIn(self.source.read_text(),text)
        self.assertEqual((self.root/'profiles/multistream/1.env').read_text(),text)
        self.assertFalse((self.root/'volga-drafts/multistream/1.urls').exists())

    def test_failed_service_restores_config_and_retains_draft(self):
        before=(self.root/'instances/1.env').read_bytes();self.failed_setup()
        with self.assertRaises(subprocess.CalledProcessError):self.configure_with_service(fail=True)
        self.assertEqual((self.root/'instances/1.env').read_bytes(),before)
        self.assertFalse((self.root/'profiles/multistream/1.env').exists())
        self.assertTrue((self.root/'volga-drafts/multistream/1.urls').exists())

if __name__=='__main__':unittest.main()
