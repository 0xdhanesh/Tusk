"""Offline tests: no Apple login, iPhone, network or Homebrew required."""
from __future__ import annotations

import asyncio
import os
import plistlib
import socket
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from ipalab import core


class CoreTests(unittest.TestCase):
    def test_app_search_json(self):
        body = '[{"name":"Liv X - Mobile Banking", "bundleID":"me.livx.ios"}]'
        self.assertEqual(core.parse_search(body)[0]["bundleID"], "me.livx.ios")

    def test_app_search_pretty_json_with_cli_prefix(self):
        output = '$ ipatool search Liv X\n{\n  "apps": [ { "name": "Liv X", "bundleID": "me.livx.ios" } ]\n}\n'
        self.assertEqual(core.parse_search(output)[0]["name"], "Liv X")

    def test_app_search_unknown(self):
        self.assertEqual(core.parse_search("no results"), [])

    def test_otool_encryption(self):
        raw = 'Load command 21\n      cmd LC_ENCRYPTION_INFO_64\n  cmdsize 24\n cryptoff 16384\n cryptsize 173686784\n   cryptid 1\n  pad 0\n'
        self.assertEqual(core.parse_otool(raw), [(1, 173686784)])

    def test_otool_clear(self):
        self.assertEqual(core.parse_otool('Load command 0\ncmd LC_ENCRYPTION_INFO_64\ncryptsize 10\ncryptid 0\n'), [(0, 10)])

    def test_next_free_port_skips_busy(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            busy = sock.getsockname()[1]
            self.assertFalse(core.free_port(busy))
            if busy < 65535:
                self.assertNotEqual(core.next_free_port(busy, min(busy + 10, 65535)), busy)

    def test_unique_output_name(self):
        with tempfile.TemporaryDirectory() as temp:
            old = Path(temp) / 'already.ipa'
            old.write_bytes(b'keep this')
            new = core.unique_ipa_path(old)
            self.assertNotEqual(old, new)
            self.assertFalse(new.exists())
            self.assertEqual(old.read_bytes(), b'keep this')

    def test_input_path_space(self):
        path = core.safe_ipa_path('~/Downloads/My Bank App.ipa')
        self.assertIn('My Bank App.ipa', str(path))
        with self.assertRaises(core.WorkflowError):
            core.safe_ipa_path('~/Downloads/not-ipa.zip')

    def test_reject_zip_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / 'attack.ipa'
            with ZipFile(archive, 'w') as z:
                z.writestr('../escape.txt', 'invalid')
            with ZipFile(archive) as z:
                with self.assertRaises(core.WorkflowError):
                    core.guarded_members(z)

    def test_plist_rewrite_only_to_15(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'source.ipa'
            target = Path(temp) / 'output.ipa'
            name = 'Payload/My Bank.app/Info.plist'
            with ZipFile(source, 'w') as z:
                z.writestr(name, plistlib.dumps({'MinimumOSVersion': '16.0', 'CFBundleExecutable':'App'}))
                z.writestr('Payload/My Bank.app/App', b'testbinary')
            core.set_min_ios(source, target, 'Payload/My Bank.app')
            with ZipFile(target) as z:
                props = plistlib.loads(z.read(name))
                self.assertEqual(props['MinimumOSVersion'], '15.0')
                self.assertEqual(z.read('Payload/My Bank.app/App'), b'testbinary')

    def test_exclusive_copy_and_refusal_to_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            src, dest = Path(temp) / 'src.ipa', Path(temp) / 'dest.ipa'
            with ZipFile(src, 'w') as z:
                z.writestr('Payload/a.app/Info.plist', b'hello')
            core.exclusive_verified_copy(src, dest)
            self.assertEqual(src.read_bytes(), dest.read_bytes())
            with self.assertRaises(FileExistsError):
                core.exclusive_verified_copy(src, dest)
            self.assertEqual(src.read_bytes(), dest.read_bytes())

    def test_ssh_root_uid_exact(self):
        class FakeRunner:
            def __init__(self, uid): self.uid=uid
            def run(self, *args, **kwargs): return (0, '$ ssh -p 2222 root@127.0.0.1 id -u\n' + self.uid)
        self.assertFalse(core.test_root_ssh(2222, FakeRunner('1000')))
        self.assertTrue(core.test_root_ssh(2222, FakeRunner('0')))

    def test_key_install_does_not_reset_root_password(self):
        command = core.root_key_command('ssh-ed25519 AAAA fake-key')
        self.assertIn('authorized_keys', command)
        self.assertNotIn('passwd', command)


class DesktopSourceTests(unittest.TestCase):
    """Static contract tests because PySide6 cannot be loaded on the CI Linux host."""

    def test_desktop_syntax(self):
        import ast
        root = Path(__file__).parents[1]
        for rel in ('ipa_lab.py', 'ipalab/desktop.py'):
            ast.parse((root / rel).read_text(encoding='utf-8'), filename=rel)

    def test_desktop_has_all_recovery_stages(self):
        import ast
        root = Path(__file__).parents[1]
        source = (root / 'ipalab/desktop.py').read_text(encoding='utf-8')
        syntax = ast.parse(source)
        classes = [n for n in syntax.body if isinstance(n, ast.ClassDef) and n.name == 'LabWindow']
        self.assertEqual(len(classes), 1)
        methods = {n.name for n in classes[0].body if isinstance(n, ast.FunctionDef)}
        for method in ('fail', 'retry', 'begin_auto_wait', 'cancel_task', 'start_tunnel',
                       'use_free_port', 'unique_download', 'use_existing_download',
                       'retrieve', 'decrypt', 'export', 'closeEvent'):
            self.assertIn(method, methods)

    def test_independent_worker_thread(self):
        import ast
        root = Path(__file__).parents[1]
        node = ast.parse((root / 'ipalab/desktop.py').read_text(encoding='utf-8'))
        jobs = [n for n in node.body if isinstance(n, ast.ClassDef) and n.name == 'Job']
        self.assertEqual(len(jobs), 1)
        self.assertTrue(any(isinstance(b, ast.Name) and b.id == 'QThread' for b in jobs[0].bases))

    def test_warm_rose_theme_and_native_ui(self):
        root = Path(__file__).parents[1]
        theme = (root / 'ipalab/theme.qss').read_text()
        self.assertIn('QPushButton#primary', theme)
        self.assertIn('#sidebarStep', theme)
        self.assertIn('#e8a3b9', theme)
        self.assertIn('QPlainTextEdit', theme)

    def test_launcher_approval_before_dependency_install(self):
        root = Path(__file__).parents[1]
        launcher = (root / 'ipa_lab.py').read_text()
        self.assertIn('if not ask(', launcher)
        self.assertIn('python@3.13', launcher)
        self.assertIn('venv', launcher)

    def test_safe_device_key_setup_does_not_reset_root_password(self):
        root = Path(__file__).parents[1]
        source = (root / 'ipalab/desktop.py').read_text()
        self.assertIn('authorized_keys', core.root_key_command('ssh-ed25519 AAAA fake'))
        self.assertNotIn('echo root:root | chpasswd', source)


if __name__ == '__main__':
    unittest.main()
