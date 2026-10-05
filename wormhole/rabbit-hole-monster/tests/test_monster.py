import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rabbit_hole_monster as rhm


def command(op, **args):
    return dict(protocol='luna-wormhole', version=1, target=rhm.TARGET, id='test-001', op=op, args=args)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'sambar70'
        self.root.mkdir()
        (self.root / 'worlds').mkdir()
        (self.root / 'worlds' / 'old.wrl').write_bytes(b'#VRML V2.0 utf8\nhello')
        (self.root / 'readme.txt').write_bytes(b'archive notes')
        (self.root / 'packed.gz').write_bytes(gzip.compress(b'A' * 2000000))
        self.archive = rhm.Archive(self.root)
        self.original = self.snapshot()

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file() and not p.is_symlink()}

    def tearDown(self):
        self.temp.cleanup()

    def runop(self, op, **args):
        return rhm.process(self.archive, command(op, **args), 'test-001')

    def test_operations_do_not_change_archive(self):
        for op, args in [('list', {}), ('search', {'pattern': '*.wrl'}), ('stat', {'path': 'readme.txt'}),
                         ('hash', {'path': 'readme.txt'}), ('read', {'path': 'readme.txt'})]:
            self.assertTrue(self.runop(op, **args)['ok'])
        self.assertEqual(self.snapshot(), self.original)

    def test_escape_and_windows_special_paths(self):
        for path in ['../secret', '/etc/passwd', 'G:\\sambar70\\readme.txt', 'G:readme.txt',
                     '\\\\server\\share', '\\\\?\\G:\\sambar70', 'a/../../b', 'readme.txt:secret',
                     'NUL', 'COM1.txt', 'a.', 'a ', 'a//b', 'a\x00b', 'sambar70/../readme.txt']:
            with self.subTest(path=path):
                self.assertFalse(self.runop('read', path=path)['ok'])

    def test_unknown_operations_and_arguments(self):
        for op in ['exec', 'write', 'write_file', 'delete', 'rename', 'shell', 'eval']:
            self.assertFalse(self.runop(op, path='readme.txt')['ok'])
        self.assertFalse(self.runop('read', path='readme.txt', root='C:\\')['ok'])

    def test_protocol_validation(self):
        for key, value in [('version', True), ('version', 2), ('protocol', 'other'), ('target', 'pi'), ('id', '../bad')]:
            c = command('ping'); c[key] = value
            self.assertFalse(rhm.process(self.archive, c, 'test-001')['ok'])
        for c in [None, [], 'hello', {'op': 'ping'}]:
            self.assertFalse(rhm.process(self.archive, c, 'test-001')['ok'])

    def test_read_and_hash(self):
        r = self.runop('read', path='readme.txt', offset=2, length=4)['result']
        self.assertEqual(base64.b64decode(r['content']), b'chiv')
        self.assertTrue(r['more'])
        self.assertEqual(self.runop('hash', path='readme.txt')['result']['digest'], hashlib.sha256(b'archive notes').hexdigest())
        self.assertFalse(self.runop('read', path='readme.txt', length=65537)['ok'])
        self.assertFalse(self.runop('read', path='readme.txt', offset=-1)['ok'])
        self.assertFalse(self.runop('read', path='readme.txt', length=True)['ok'])

    def test_gzip_is_bounded(self):
        r = self.runop('read', path='packed.gz', gzip=True, length=64, encoding='utf-8')['result']
        self.assertEqual(r['content'], 'A' * 64)
        self.assertTrue(r['more'])
        self.assertFalse(self.runop('read', path='packed.gz', gzip=True, offset=1048576)['ok'])
        self.assertFalse(self.runop('read', path='readme.txt', gzip=True)['ok'])

    def test_pagination_and_search(self):
        a = self.runop('list', limit=2)['result']
        b = self.runop('list', offset=a['next_offset'], limit=2)['result']
        self.assertEqual(len(a['entries']) + len(b['entries']), 3)
        self.assertFalse(b['truncated'])
        r = self.runop('search', pattern='*.WRL')['result']
        self.assertEqual([e['path'] for e in r['entries']], ['worlds/old.wrl'])

    def test_symlink_escape(self):
        outside = self.base / 'outside'; outside.mkdir()
        (outside / 'secret').write_text('secret')
        try:
            (self.root / 'link').symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('symlink creation unavailable')
        self.assertFalse(self.runop('read', path='link/secret')['ok'])
        result = self.runop('search')['result']
        self.assertEqual(result['skipped'], 1)
        self.assertFalse(any('secret' in e['path'] for e in result['entries']))

    def test_hardlink_escape(self):
        secret = self.base / 'secret'; secret.write_text('secret')
        os.link(secret, self.root / 'hardlink')
        self.assertFalse(self.runop('read', path='hardlink')['ok'])

    def test_missing_root_fails_closed(self):
        a = rhm.Archive(self.base / 'missing')
        self.assertFalse(rhm.process(a, command('list'), 'test-001')['ok'])

    @unittest.skipUnless(os.name == 'nt', 'Windows junction boundary test')
    def test_windows_junction_escape(self):
        outside = self.base / 'outside'; outside.mkdir()
        (outside / 'secret').write_text('secret')
        link = self.root / 'junction'
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(outside)], check=True, capture_output=True)
        try:
            self.assertFalse(self.runop('read', path='junction/secret')['ok'])
        finally:
            link.rmdir()

    @unittest.skipUnless(os.name == 'nt', 'Windows rename pinning test')
    def test_windows_path_is_pinned(self):
        with self.archive.guard('worlds/old.wrl'):
            with self.assertRaises(OSError):
                (self.root / 'worlds').rename(self.root / 'moved')


class FakeGitHub:
    def __init__(self):
        self.document = command('read', path='readme.txt', encoding='utf-8')
        self.output = None
        self.fail = False
        self.puts = 0

    def get(self, path):
        if path.endswith('/inbox'):
            return [dict(name='test-001.json', type='file')]
        if '/outbox/' in path:
            return self.output
        raw = json.dumps(self.document).encode()
        return dict(size=len(raw), content=base64.b64encode(raw).decode())

    def put(self, path, document):
        self.puts += 1
        if self.fail:
            raise OSError('simulated disconnect')
        self.output = document


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'archive'; self.root.mkdir()
        (self.root / 'readme.txt').write_text('original')
        self.state = Path(self.temp.name) / 'state'; self.state.mkdir()
        self.archive = rhm.Archive(self.root)
        self.github = FakeGitHub()

    def tearDown(self):
        self.temp.cleanup()

    def test_roundtrip_and_replay(self):
        rhm.poll(self.github, self.archive, self.state)
        self.assertEqual(self.github.output['result']['content'], 'original')
        rhm.poll(self.github, self.archive, self.state)
        self.assertEqual(self.github.puts, 1)
        events = [json.loads(line)['event'] for line in (self.state / 'audit.jsonl').read_text().splitlines()]
        self.assertEqual(events, ['request', 'response', 'published'])

    def test_retry_uses_durable_response(self):
        self.github.fail = True
        with self.assertRaises(OSError):
            rhm.poll(self.github, self.archive, self.state)
        (self.root / 'readme.txt').write_text('changed')
        self.github.fail = False
        rhm.poll(self.github, self.archive, self.state)
        self.assertEqual(self.github.output['result']['content'], 'original')

    def test_existing_response_is_never_overwritten(self):
        self.github.output = {'existing': True}
        rhm.poll(self.github, self.archive, self.state)
        self.assertEqual(self.github.puts, 0)
        self.assertTrue((self.state / 'test-001.done').exists())

    def test_bad_request_does_not_poison_worker(self):
        self.github.document = []
        rhm.poll(self.github, self.archive, self.state)
        self.assertFalse(self.github.output['ok'])


if __name__ == '__main__':
    unittest.main()
