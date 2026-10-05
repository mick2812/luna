"""Read-only Sambar archive worker. Python 3.11+, standard library only."""
from __future__ import annotations
import argparse
import base64
import contextlib
import ctypes
import fnmatch
import getpass
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone

ROOT = r'\\Bigdaddy\g\sambar70'
REPO = 'mick2812/luna'
BRANCH = 'main'
MAILBOX = 'wormhole/windows-sambar'
TARGET = 'windows-sambar'
OPS = ('ping', 'capabilities', 'list', 'search', 'stat', 'hash', 'read', 'catalog_start', 'catalog_next')
MAX_READ = 65536
MAX_HASH = 256 * 1024 * 1024
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
RESERVED = re.compile(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', re.I)


def now():
    return datetime.now(timezone.utc).isoformat()


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('numeric argument outside allowed range')
    return value


def parts(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError('path must be a relative string')
    if value in ('', '.'):
        return ()
    value = value.replace('\\', '/')
    result = value.split('/')
    if any(not p or p in ('.', '..') or p.endswith((' ', '.')) or
           any(ord(c) < 32 or c in ':*?"<>|' for c in p) or RESERVED.match(p)
           for p in result):
        raise ValueError('unsafe path')
    return tuple(result)


@contextlib.contextmanager
def windows_lock(path):
    """Pin path against rename/deletion and reject every reparse point by handle."""
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    create.restype = w.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [w.HANDLE]
    class Info(ctypes.Structure):
        _fields_ = [('attributes', w.DWORD), ('creation', w.FILETIME),
                    ('access', w.FILETIME), ('write', w.FILETIME),
                    ('volume', w.DWORD), ('sizeHigh', w.DWORD), ('sizeLow', w.DWORD),
                    ('links', w.DWORD), ('indexHigh', w.DWORD), ('indexLow', w.DWORD)]
    getinfo = kernel.GetFileInformationByHandle
    getinfo.argtypes = [w.HANDLE, ctypes.POINTER(Info)]
    # READ_ATTRIBUTES; share READ/WRITE, deliberately omit DELETE.
    handle = create(str(path), 0x80, 3, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        code = ctypes.get_last_error()
        raise OSError(code, 'cannot lock archive path: ' + ctypes.FormatError(code).strip(), str(path))
    try:
        info = Info()
        if not getinfo(handle, ctypes.byref(info)):
            raise OSError('cannot inspect archive handle')
        if info.attributes & 0x400:
            raise ValueError('reparse points are not allowed')
        if not info.attributes & 0x10 and info.links != 1:
            raise ValueError('hard-linked files are not allowed')
        yield
    finally:
        close(handle)


class Archive:
    def __init__(self, root):
        self.root = Path(root).absolute()

    @contextlib.contextmanager
    def guard(self, relative=''):
        segments = parts(relative)
        target = self.root.joinpath(*segments)
        # Pin every ancestor, including ancestors of the configured root.
        chain = list(reversed(self.root.parents)) + [self.root]
        chain += [self.root.joinpath(*segments[:i]) for i in range(1, len(segments) + 1)]
        with contextlib.ExitStack() as stack:
            for path in chain:
                if os.name == 'nt':
                    stack.enter_context(windows_lock(path))
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                    raise ValueError('links and reparse points are not allowed')
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise ValueError('special files are not allowed')
                if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                    raise ValueError('hard-linked files are not allowed')
            target.resolve(strict=True).relative_to(self.root.resolve(strict=True))
            yield target

    def metadata(self, relative):
        with self.guard(relative) as p:
            s = p.stat()
            return dict(path=relative or '.', kind='directory' if p.is_dir() else 'file',
                        size=s.st_size, modified_ns=s.st_mtime_ns)

    def execute(self, op, args):
        allowed = {'ping': set(), 'capabilities': set(), 'stat': {'path'},
                   'hash': {'path'}, 'list': {'path', 'offset', 'limit'},
                   'search': {'path', 'pattern', 'offset', 'limit'},
                   'read': {'path', 'offset', 'length', 'encoding', 'gzip'}}
        if op not in allowed or not isinstance(args, dict) or set(args) - allowed[op]:
            raise ValueError('operation or arguments not allowed')
        if op == 'ping':
            return 'PONG FROM RABBIT HOLE MONSTER'
        if op == 'capabilities':
            return dict(root=ROOT, operations=list(OPS), read_only=True,
                        max_read_bytes=MAX_READ, max_hash_bytes=MAX_HASH,
                        search='recursive filename glob; no content execution',
                        transport=MAILBOX, public_results=True)
        rel = '/'.join(parts(args.get('path', '')))
        if op == 'stat':
            return self.metadata(rel)
        if op in ('list', 'search'):
            offset = integer(args.get('offset', 0), 0, 100000)
            limit = integer(args.get('limit', 100), 1, 500)
            pattern = args.get('pattern', '*')
            if not isinstance(pattern, str) or not 1 <= len(pattern) <= 200:
                raise ValueError('invalid filename pattern')
            entries, skipped, seen, visited = [], 0, 0, 0
            deadline = time.monotonic() + 20
            pending = [rel]
            while pending:
                directory = pending.pop()
                with self.guard(directory) as folder:
                    if not folder.is_dir():
                        raise ValueError('directory required')
                    # Bound enumeration even for enormous directories.
                    with os.scandir(folder) as scan:
                        children = []
                        for child in scan:
                            visited += 1
                            if visited > 100000 or time.monotonic() > deadline:
                                return dict(entries=entries, skipped=skipped, truncated=True,
                                            next_offset=None, warning='scan budget reached; narrow path')
                            children.append(child.name)
                for name in sorted(children, key=lambda s: (s.casefold(), s)):
                    if time.monotonic() > deadline:
                        return dict(entries=entries, skipped=skipped, truncated=True,
                                    next_offset=None, warning='scan budget reached; narrow path')
                    childrel = '/'.join(filter(None, (directory, name)))
                    try:
                        info = self.metadata(childrel)
                    except (OSError, ValueError):
                        skipped += 1
                        continue
                    if op == 'search' and info['kind'] == 'directory':
                        pending.append(childrel)
                    if op == 'search' and not fnmatch.fnmatchcase(name.casefold(), pattern.casefold()):
                        continue
                    seen += 1
                    if seen <= offset:
                        continue
                    if len(entries) == limit:
                        return dict(entries=entries, skipped=skipped, truncated=True,
                                    next_offset=offset + len(entries))
                    entries.append(info)
                if op == 'list':
                    break
            return dict(entries=entries, skipped=skipped, truncated=False, next_offset=None)
        with self.guard(rel) as p:
            if not p.is_file():
                raise ValueError('regular file required')
            with p.open('rb') as raw:
                before = os.fstat(raw.fileno())
                if op == 'hash':
                    if before.st_size > MAX_HASH:
                        raise ValueError('file exceeds hash size limit')
                    h = hashlib.sha256()
                    total = 0
                    while chunk := raw.read(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_HASH:
                            raise ValueError('file exceeds hash size limit')
                        h.update(chunk)
                    result = dict(path=rel, algorithm='sha256', digest=h.hexdigest(), bytes=total)
                else:
                    offset = integer(args.get('offset', 0), 0, 2**40)
                    length = integer(args.get('length', 16384), 1, MAX_READ)
                    encoding = args.get('encoding', 'base64')
                    if encoding not in ('base64', 'utf-8', 'cp1252'):
                        raise ValueError('unsupported encoding')
                    compressed = args.get('gzip', False)
                    if type(compressed) is not bool:
                        raise ValueError('gzip must be boolean')
                    if compressed and offset + length > 1024 * 1024:
                        raise ValueError('gzip decompression limited to first 1 MiB')
                    with contextlib.ExitStack() as stack:
                        stream = stack.enter_context(gzip.GzipFile(fileobj=raw)) if compressed else raw
                        stream.seek(offset)
                        data = stream.read(length + 1)
                    more = len(data) > length
                    data = data[:length]
                    content = base64.b64encode(data).decode('ascii') if encoding == 'base64' else data.decode(encoding, errors='replace')
                    result = dict(path=rel, offset=offset, bytes=len(data), encoding=encoding,
                                  content=content, more=more, next_offset=offset + len(data) if more else None)
                after = os.fstat(raw.fileno())
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ValueError('file changed during read; retry')
                return result


def catalog_step(archive, state_dir, command):
    op = command.get('op')
    args = command.get('args', {})
    if not isinstance(args, dict):
        raise ValueError('arguments must be an object')
    if op == 'catalog_start':
        if set(args) - {'path'}:
            raise ValueError('operation or arguments not allowed')
        root = '/'.join(parts(args.get('path', '')))
        with archive.guard(root) as folder:
            if not folder.is_dir():
                raise ValueError('catalogue root must be a directory')
        job = command['id']
        jobfile = state_dir / (job + '.catalog.json')
        if jobfile.exists():
            raise ValueError('catalogue job already exists; use a new request id')
        data = {'root': root, 'pending': [{'path': root, 'offset': 0}],
                'complete': False, 'processed': 0}
    elif op == 'catalog_next':
        if set(args) != {'job'} or not isinstance(args.get('job'), str) or not ID.fullmatch(args['job']):
            raise ValueError('catalog_next requires a valid job id')
        job = args['job']
        jobfile = state_dir / (job + '.catalog.json')
        if not jobfile.exists():
            raise ValueError('catalogue job not found')
        data = json.loads(jobfile.read_text(encoding='utf-8'))
    else:
        raise ValueError('operation not allowed')

    entries, skipped = [], 0
    deadline = time.monotonic() + 15
    while data['pending'] and len(entries) < 250 and time.monotonic() < deadline:
        current = data['pending'].pop(0)
        page = archive.execute('list', {'path': current['path'], 'offset': current['offset'],
                                        'limit': min(250, 250 - len(entries))})
        entries.extend(page['entries'])
        skipped += page['skipped']
        for item in page['entries']:
            if item['kind'] == 'directory':
                data['pending'].append({'path': item['path'], 'offset': 0})
        if page['truncated'] and page['next_offset'] is not None:
            data['pending'].append({'path': current['path'], 'offset': page['next_offset']})
        data['processed'] += len(page['entries'])
        if not page['entries'] and page['truncated']:
            # Avoid a tight loop if a single enormous directory cannot make progress.
            data['pending'].insert(0, current)
            break
    data['complete'] = not data['pending']
    temp = jobfile.with_suffix('.tmp')
    temp.write_text(json.dumps(data), encoding='utf-8')
    temp.replace(jobfile)
    return dict(job=job, root=data['root'], entries=entries, skipped=skipped,
                complete=data['complete'], processed=data['processed'],
                remaining_directories=len(data['pending']),
                next_operation=None if data['complete'] else 'catalog_next',
                next_args=None if data['complete'] else {'job': job})


def process(archive, command, request_id, state_dir=None):
    response = dict(protocol='luna-wormhole', version=1, target=TARGET, id=request_id,
                    op=command.get('op') if isinstance(command, dict) else None, processed_at=now())
    try:
        if (not isinstance(command, dict) or set(command) - {'protocol', 'version', 'target', 'id', 'op', 'args'}
            or command.get('protocol') != 'luna-wormhole' or type(command.get('version')) is not int
            or command.get('version') != 1 or command.get('target') != TARGET
            or command.get('id') != request_id or not ID.fullmatch(request_id)):
            raise ValueError('invalid request envelope')
        if command.get('op') in ('catalog_start', 'catalog_next'):
            if state_dir is None:
                raise ValueError('catalogue state unavailable')
            result = catalog_step(archive, state_dir, command)
        else:
            result = archive.execute(command.get('op'), command.get('args', {}))
        response.update(ok=True, result=result)
    except (ValueError, OSError, EOFError, TypeError, zlib.error) as exc:
        # No absolute paths, tokens, or exception bodies in remote diagnostics.
        response.update(ok=False, error=str(exc) if isinstance(exc, ValueError) else 'archive read failed',
                        error_type=type(exc).__name__)
    return response


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('GitHub redirects refused')


class GitHub:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, body=None):
        url = f'https://api.github.com/repos/{REPO}/' + path
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Rabbit-Hole-Monster/1.0'}
        encoded = None if body is None else json.dumps(body).encode('utf-8')
        if encoded is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=encoded, headers=headers, method=method)
        with self.opener.open(req, timeout=30) as response:
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError('GitHub response too large')
            return json.loads(data)

    def get(self, path):
        try:
            return self.request('GET', 'contents/' + urllib.parse.quote(path, safe='/') + '?ref=' + BRANCH)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def put(self, path, document):
        return self.request('PUT', 'contents/' + path,
                            dict(message='Rabbit Hole Monster response: ' + document['id'], branch=BRANCH,
                                 content=base64.b64encode((json.dumps(document) + '\n').encode()).decode()))


def audit(state, event, **fields):
    with (state / 'audit.jsonl').open('a', encoding='utf-8') as log:
        log.write(json.dumps(dict(at=now(), event=event, **fields)) + '\n')


def poll(github, archive, state):
    items = github.get(MAILBOX + '/inbox') or []
    if not isinstance(items, list):
        raise ValueError('invalid inbox listing')
    if len(items) >= 1000:
        raise ValueError('inbox directory at GitHub limit; archive completed requests')
    for item in items:
        name = item.get('name', '')
        if item.get('type') != 'file' or not name.endswith('.json') or not ID.fullmatch(name[:-5]):
            continue
        request_id = name[:-5]
        done = state / (request_id + '.done')
        if done.exists():
            continue
        outpath = MAILBOX + '/outbox/' + name
        if github.get(outpath) is not None:
            audit(state, 'existing_response', id=request_id)
            done.touch()
            continue
        pending = state / (request_id + '.pending.json')
        if pending.exists():
            response = json.loads(pending.read_text(encoding='utf-8'))
        else:
            content = github.get(MAILBOX + '/inbox/' + name)
            if content is None:
                continue
            try:
                if content.get('size', 0) > 16384:
                    raise ValueError('request too large')
                raw = base64.b64decode(content['content'])
                if len(raw) > 16384:
                    raise ValueError('request too large')
                command = json.loads(raw)
            except (ValueError, KeyError, RecursionError):
                command = None
            audit(state, 'request', id=request_id, command=command)
            response = process(archive, command, request_id, state)
            temp = pending.with_suffix('.tmp')
            temp.write_text(json.dumps(response), encoding='utf-8')
            temp.replace(pending)
            audit(state, 'response', id=request_id, response=response)
        github.put(outpath, response)
        audit(state, 'published', id=request_id)
        done.touch()
        pending.unlink(missing_ok=True)
        print('Completed:', request_id, 'OK' if response['ok'] else 'rejected', flush=True)


@contextlib.contextmanager
def single_instance(state):
    import msvcrt
    with (state / 'worker.lock').open('a+b') as lock:
        if lock.tell() == 0:
            lock.write(b'0')
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise ValueError('another Rabbit Hole Monster is already running')
        try:
            yield
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def environment_token():
    """Read only the two supported token variables; never print their values."""
    names = ('GITHUB_TOKEN', 'GH_TOKEN')
    for name in names:
        value = os.environ.get(name, '').strip()
        if value:
            return value
    if os.name == 'nt':
        import winreg
        locations = (
            (winreg.HKEY_CURRENT_USER, 'Environment'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'),
        )
        for hive, path in locations:
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                    for name in names:
                        try:
                            value, kind = winreg.QueryValueEx(key, name)
                        except OSError:
                            continue
                        if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(value, str):
                            if kind == winreg.REG_EXPAND_SZ:
                                value = winreg.ExpandEnvironmentStrings(value)
                            if value.strip():
                                return value.strip()
            except OSError:
                continue
    return ''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true', help='poll once and stop')
    parser.add_argument('--check', action='store_true', help='check archive boundary without network')
    options = parser.parse_args()
    if os.name != 'nt':
        parser.error('The live helper runs only on Windows; tests use temporary fixtures.')
    archive = Archive(ROOT)
    print('Checking archive:', ROOT, flush=True)
    try:
        root_info = archive.root.lstat()
    except OSError as exc:
        raise ValueError(
            f'Windows cannot access {ROOT!r} (Windows error {exc.winerror}). '
            'Check this exact folder in File Explorer and run the helper as your normal user, '
            'not as administrator. No archive requests have been processed.'
        ) from None
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError(f'Archive root is not a directory: {ROOT}')
    with archive.guard() as root:
        if not root.is_dir():
            raise ValueError('archive root is not a directory')
    if options.check:
        print('Archive boundary OK:', ROOT)
        return
    token = environment_token()
    if not token:
        print('No GITHUB_TOKEN or GH_TOKEN found in this process or saved Windows environment.')
        token = getpass.getpass('GitHub token (hidden; not saved): ')
    if not token.strip():
        raise ValueError('GitHub token is required')
    state = Path(os.environ['LOCALAPPDATA']) / 'Luna' / 'RabbitHoleMonster'
    # Local state must never be placed inside the archive, even through a link.
    if state.resolve().is_relative_to(Path(ROOT).resolve()):
        raise ValueError('state directory must be outside archive')
    state.mkdir(parents=True, exist_ok=True)
    github = GitHub(token.strip())
    print('Rabbit Hole Monster: READ ONLY', ROOT)
    print('Public GitHub results:', REPO, MAILBOX)
    print('Ctrl+C stops the helper. Local audit:', state / 'audit.jsonl', flush=True)
    with single_instance(state):
        delay = 10
        while True:
            try:
                poll(github, archive, state)
                delay = 10
            except (OSError, ValueError, KeyError) as exc:
                code = getattr(exc, 'code', None)
                audit(state, 'transport_error', error_type=type(exc).__name__, http_status=code)
                print('Transport problem:', type(exc).__name__, code or '', '— retrying', flush=True)
                if options.once:
                    raise SystemExit(1)
                delay = min(300, max(30, delay * 2))
            if options.once:
                break
            time.sleep(delay)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nRabbit Hole Monster stopped.')
    except (ValueError, OSError) as exc:
        print('Startup failed:', str(exc), file=sys.stderr)
        sys.exit(1)
