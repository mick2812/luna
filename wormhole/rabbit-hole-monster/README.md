# Rabbit Hole Monster — Sambar archive helper

A read-only Windows worker for Michael's `\\Bigdaddy\g\sambar70` archive, using the existing
`mick2812/luna` GitHub wormhole. Python 3.11 or newer; no pip packages needed.

## Start

Download the repository ZIP, extract it somewhere outside `\\Bigdaddy\g\sambar70`, open
`wormhole/rabbit-hole-monster`, and double-click `Start-Rabbit-Hole-Monster.cmd`.
The launcher finds Python automatically. If `GITHUB_TOKEN` is already set it is
reused; otherwise a hidden prompt asks for a token for this session only. Use a
fine-grained token restricted to `mick2812/luna`, Contents: read and write.
Never put the token into a request, source file, repository, or chat.

Leave the window open while using the helper; Ctrl+C stops it. No administrator
rights, service installation, startup task, inbound port, or config editing is
required. The configured archive root cannot be changed by remote requests.

**The repository is public. Every published response, including requested file
contents and filenames, is public and remains in Git history.** Read requests
should therefore select material intended for this transport. Starting the
helper processes queued requests in its dedicated mailbox. The supplied initial
request only reports capabilities; it does not enumerate or read archive files.

## Transport

* Requests: `wormhole/windows-sambar/inbox/<id>.json`
* Responses: `wormhole/windows-sambar/outbox/<id>.json`
* Branch: `main`; poll interval: 10 seconds, exponential error backoff to 5 minutes.

The dedicated directory prevents the existing Pi worker from consuming Windows
commands. The original Pi inbox, worker, and outbox are untouched. This preserves
the `luna-wormhole` v1 envelope and adds a required `target` field and `args` object.

```json
{
  "protocol": "luna-wormhole",
  "version": 1,
  "target": "windows-sambar",
  "id": "sambar-worlds-001",
  "op": "search",
  "args": {"path": "", "pattern": "*.wrl", "limit": 100}
}
```

Use a unique ID for every request; IDs are 1–80 ASCII letters, digits, `_` or `-`,
starting with a letter or digit, and must match the filename. Filesystem paths
are relative to the fixed root. Empty path means the archive root.

| Operation | Arguments | Result |
|---|---|---|
| `ping` | none | Worker greeting |
| `capabilities` | none | Root, operations and limits |
| `list` | `path`, `offset`, `limit` | Immediate children and metadata |
| `search` | `path`, `pattern`, `offset`, `limit` | Recursive, case-insensitive filename glob |
| `stat` | `path` | Type, byte size, modification time in ns |
| `hash` | `path` | SHA-256, up to 256 MiB |
| `read` | `path`, `offset`, `length`, `encoding`, `gzip` | Bounded file bytes/text |

Lists default to 100 entries and permit 500; use `next_offset` for another page.
Pagination assumes a stable archive; concurrent changes can shift pages. A search
visits at most 100,000 entries and has a time budget. If a scan reaches its budget,
`truncated` is true with a warning; narrow the starting path instead of assuming a
complete result. Links, inaccessible entries, and unsafe names are skipped and
counted. Search examines filenames, not file contents.

Reads default to 16 KiB, maximum 64 KiB per response. Default encoding is base64
for exact recovery; `utf-8` and `cp1252` previews replace undecodable bytes. Text
pages can split a multibyte character; use base64 for lossless assembly. Set
`gzip: true` for in-memory decompression, bounded to the first 1 MiB. No files are
extracted or executed. Hashes/read results are rejected if observed size or
modification time changes during the operation; the archive is not a snapshot.

## Boundary and local state

There are no write, delete, rename, upload-to-archive, execute, shell, plugin, or
remote update commands. Absolute paths, traversal, alternate streams, device
names, symlinks, reparse points (including junctions), hard-linked files, and
special files are rejected. On Windows, each ancestor is opened and pinned
against rename/deletion for the duration of each filesystem operation. This is
an application boundary, not an OS sandbox against a malicious local admin.
Read-only refers to archive contents; the filesystem may update access times.

The helper writes only its own state and audit files under
`%LOCALAPPDATA%\Luna\RabbitHoleMonster` and responses in GitHub. Audit entries
include complete valid requests and generated responses, including read content;
they do not include the GitHub token. State/audit files remain local. Pending
responses persist before upload, so a failed upload is retried with the same
result after restart. Existing remote responses are never overwritten. A local
lock prevents two workers using the same Windows profile. Use one PC worker per
mailbox. No automatic deletion or pruning is performed. Archive completed inbox
requests before the mailbox reaches GitHub's 1,000-entry directory limit.

## Tests

`Test-Rabbit-Hole-Monster.cmd` runs the fixture tests and checks the real archive
root without contacting GitHub or reading its file contents. From a terminal:

```
python -m unittest discover -s tests -v
python rabbit_hole_monster.py --check
```

The CI workflow runs the suite on Linux and Windows. Windows-only tests cover
junction escape and rename prevention while a path is pinned; Linux skips these.
Transport tests use a fake GitHub API and verify roundtrip, duplicate suppression,
malformed requests, and durable retry. Live PC connectivity is proven only when
a response appears in the Windows outbox after the helper starts.
