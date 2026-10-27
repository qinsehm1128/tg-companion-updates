#!/usr/bin/env python3
"""Only publish signed binary update assets; never source, account data or debug builds."""
import argparse
import base64
import hashlib
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

REPOSITORY = 'qinsehm1128/tg-companion-updates'
ENDPOINT = f'https://github.com/{REPOSITORY}/releases/latest/download/latest.json'
PLATFORM = 'darwin-aarch64'
MAX_BYTES = 100 * 1024 * 1024
NATIVE_FILES = (
    'libtdjson.dylib', 'companion-local-reader', 'manifest.json',
    'LICENSE-TDLib.txt', 'LICENSE-OpenSSL.txt', 'LICENSE-SQLCipher.txt',
    'local-reader-licenses/DEPENDENCY_LICENSES.txt',
    'local-reader-licenses/THIRD_PARTY_NOTICES.md',
)
APP_NAME = 'Telegram Companion.app'


def version(tag):
    if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise ValueError('Expected stable vMAJOR.MINOR.PATCH; prereleases are not published as latest')
    return tag[1:]


def asset_name(tag):
    return f'Telegram-Companion_{version(tag)}_{PLATFORM}.app.tar.gz'


def regular(file):
    if file.is_symlink() or not file.is_file():
        raise ValueError(f'Expected regular non-symlink file: {file}')
    return file


def native_config(root):
    native = root / 'src-tauri/native'
    for name in NATIVE_FILES:
        regular(native / name)
    config = json.loads((root / 'src-tauri/tauri.conf.json').read_text())
    updater = config.get('plugins', {}).get('updater', {})
    if updater.get('endpoints') != [ENDPOINT] or not updater.get('pubkey', '').strip():
        raise ValueError('Configure the fixed public updater endpoint and real signing public key first')
    # Array REPLACES the development directory resource map; no directory globs.
    # In particular "companion-local-reader 2/3/4" remain on disk but never ship.
    return {'bundle': {'createUpdaterArtifacts': True,
                       'resources': ['native/' + name for name in NATIVE_FILES],
                       'macOS': {'signingIdentity': '-'}}}


def check_app(app):
    native = app / 'Contents/Resources/native'
    actual = {str(p.relative_to(native)) for p in native.rglob('*') if not p.is_dir()}
    if actual != set(NATIVE_FILES):
        raise ValueError(f'Unexpected native bundle contents: {actual ^ set(NATIVE_FILES)}')
    allowed_macho = {'Contents/MacOS/tg-companion',
                     'Contents/Resources/native/libtdjson.dylib',
                     'Contents/Resources/native/companion-local-reader'}
    for file in app.rglob('*'):
        if file.is_symlink():
            raise ValueError(f'Symlink in release app: {file}')
        if not file.is_file():
            continue
        with file.open('rb') as stream:
            magic = stream.read(4)
        relative = str(file.relative_to(app))
        if not app_file_allowed(f'{APP_NAME}/{relative}'):
            raise ValueError(f'Unexpected app file: {relative}')
        if magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe') or os.access(file, os.X_OK):
            if relative not in allowed_macho:
                raise ValueError(f'Extra executable in release app: {relative}')
    for name in NATIVE_FILES:
        regular(native / name)


def signature(file):
    text = regular(file).read_text().strip()
    if len(text) > 16384:
        raise ValueError('Oversized updater signature')
    decoded = base64.b64decode(text, validate=True)
    if not decoded.startswith(b'untrusted comment:') or b'\ntrusted comment:' not in decoded:
        raise ValueError('Expected Tauri/minisign signature, not an empty or placeholder .sig')
    return text


def verify_signature(archive, signature_text, public_key=None):
    if public_key is None:
        trust_file = Path(__file__).resolve().parent / 'updater-public-key.txt'
        if trust_file.is_file():
            public_key = trust_file.read_text().strip()
        else:
            config = json.loads((Path(__file__).resolve().parent.parent / 'src-tauri/tauri.conf.json').read_text())
            public_key = config['plugins']['updater']['pubkey']
    key_lines = base64.b64decode(public_key, validate=True).decode().splitlines()
    sig_lines = base64.b64decode(signature_text, validate=True).decode().splitlines()
    if len(key_lines) != 2 or len(sig_lines) != 4 or not sig_lines[2].startswith('trusted comment: '):
        raise ValueError('Malformed Tauri public key or signature')
    key = base64.b64decode(key_lines[1], validate=True)
    packet = base64.b64decode(sig_lines[1], validate=True)
    global_sig = base64.b64decode(sig_lines[3], validate=True)
    if len(key) != 42 or len(packet) != 74 or len(global_sig) != 64 or key[:2] != b'Ed' or packet[:2] != b'ED' or key[2:10] != packet[2:10]:
        raise ValueError('Invalid signature algorithm/key ID (prehashed minisign required)')
    digest = hashlib.blake2b(regular(archive).read_bytes()).digest()
    payload = {'key': key[10:].hex(), 'signature': packet[10:].hex(), 'digest': digest.hex(),
               'global': global_sig.hex(), 'comment': sig_lines[2][17:]}
    # Algorithm and format mirror minisign-verify (Tauri updater), not a shell verifier.
    code = """
const { createPublicKey, verify } = require('node:crypto');
const p=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const b=s=>Buffer.from(s,'hex');
const key=createPublicKey({key:Buffer.concat([b('302a300506032b6570032100'),b(p.key)]),format:'der',type:'spki'});
if (!verify(null,b(p.digest),key,b(p.signature)) || !verify(null,Buffer.concat([b(p.signature),Buffer.from(p.comment)]),key,b(p.global))) process.exit(1);
"""
    result = subprocess.run(['node', '-e', code], input=json.dumps(payload), text=True, capture_output=True)
    if result.returncode:
        raise ValueError('Updater signature verification failed against configured public key')


def app_file_allowed(name):
    prefix = f'{APP_NAME}/'
    if not name.startswith(prefix):
        return False
    relative = name[len(prefix):]
    return relative in {
        'Contents/Info.plist', 'Contents/PkgInfo', 'Contents/MacOS/tg-companion',
        'Contents/Resources/icon.icns', 'Contents/Resources/Assets.car',
        'Contents/_CodeSignature/CodeResources',
        *('Contents/Resources/native/' + name for name in NATIVE_FILES),
    }


def raw_archive_check(file):
    # tarfile.getmembers() hides PAX/GNU extension headers; the native reader does not.
    # Validate every raw 512-byte header before using tarfile's interpreted view.
    expanded = 0
    count = 0
    limit = 512 * 1024 * 1024
    with gzip.open(file, 'rb') as stream:
        while True:
            header = stream.read(512)
            expanded += len(header)
            if len(header) != 512 or expanded > limit:
                raise ValueError('Truncated or oversized raw archive')
            if not any(header):
                while chunk := stream.read(65536):
                    expanded += len(chunk)
                    if expanded > limit or any(chunk):
                        raise ValueError('Invalid archive trailing data')
                return
            count += 1
            if count > 20000 or header[156:157] not in (b'0', b'\0', b'5'):
                raise ValueError('Only plain USTAR file/directory headers are supported')
            size_field = header[124:136].strip(b'\0 ')
            if not size_field or any(byte not in b'01234567' for byte in size_field):
                raise ValueError('Invalid USTAR entry size')
            remaining = ((int(size_field, 8) + 511) // 512) * 512
            if expanded + remaining > limit:
                raise ValueError('Expanded archive exceeds 512 MiB')
            while remaining:
                chunk = stream.read(min(remaining, 65536))
                if not chunk:
                    raise ValueError('Truncated archive entry')
                remaining -= len(chunk)
                expanded += len(chunk)


def archive_check(file):
    regular(file)
    if not 0 < file.stat().st_size <= MAX_BYTES:
        raise ValueError('Update archive exceeds 100 MiB cap or is empty')
    raw_archive_check(file)
    with tarfile.open(file, 'r:gz') as archive:
        entries = archive.getmembers()
        if len({entry.name for entry in entries}) != len(entries):
            raise ValueError('Duplicate archive entry names are forbidden')
        if len(entries) > 20000 or sum(entry.size for entry in entries) > 512 * 1024 * 1024:
            raise ValueError('Unreasonable expanded app archive size or entry count')
        if not entries:
            raise ValueError('Empty update archive')
        for entry in entries:
            parts = PurePosixPath(entry.name).parts
            if entry.name.rstrip('/') != str(PurePosixPath(entry.name)) or (entry.name.endswith('/') and not entry.isdir()):
                raise ValueError('Noncanonical archive path is forbidden')
            if entry.isfile() and not app_file_allowed(entry.name):
                raise ValueError(f'Unexpected app resource: {entry.name}')
            if not parts or parts[0] != APP_NAME or '..' in parts or entry.name.startswith('/'):
                raise ValueError('Archive must contain only Telegram Companion.app, without traversal')
            if not (entry.isdir() or entry.isfile()):
                raise ValueError('Archive links/devices are forbidden')
            if any(p in ('debug', '.git', 'src', 'src-tauri', 'node_modules') for p in parts):
                raise ValueError('Source/debug/cache paths are forbidden in update archive')
        allowed_executables = {f'{APP_NAME}/Contents/MacOS/tg-companion',
                               f'{APP_NAME}/Contents/Resources/native/companion-local-reader',
                               f'{APP_NAME}/Contents/Resources/native/libtdjson.dylib'}
        names = {m.name for m in entries if m.isfile()}
        if not allowed_executables.issubset(names) or f'{APP_NAME}/Contents/Info.plist' not in names:
            raise ValueError('Missing required app executable, native libraries or Info.plist')
        for entry in entries:
            if entry.isfile():
                with archive.extractfile(entry) as stream:
                    magic = stream.read(4)
                if (entry.mode & 0o111 or magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe')) and entry.name not in allowed_executables:
                    raise ValueError('Extra executable in update archive')
        native_prefix = f'{APP_NAME}/Contents/Resources/native/'
        native = {m.name[len(native_prefix):] for m in entries if m.isfile() and m.name.startswith(native_prefix)}
        if native != set(NATIVE_FILES):
            raise ValueError('Archive native contents do not match release whitelist')


def metadata(directory, tag):
    name = asset_name(tag)
    archive = directory / name
    archive_check(archive)
    sig = signature(directory / (name + '.sig'))
    verify_signature(archive, sig)
    return {'version': version(tag),
            'notes': 'macOS arm64 release. Ad-hoc signed; not Apple notarized.',
            'pub_date': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'platforms': {PLATFORM: {
                'signature': sig,
                'url': f'https://github.com/{REPOSITORY}/releases/download/{tag}/{name}',
                'size': archive.stat().st_size,
                'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            }}}


def validate(directory, tag):
    expected = {asset_name(tag), asset_name(tag) + '.sig', 'latest.json'}
    if {file.name for file in directory.iterdir()} != expected:
        raise ValueError('Release directory must contain exactly archive, .sig and latest.json (no source/debug files)')
    actual = json.loads(regular(directory / 'latest.json').read_text())
    wanted = metadata(directory, tag)
    for key in ('version', 'platforms', 'notes'):
        if actual.get(key) != wanted[key]:
            raise ValueError(f'Invalid latest.json {key}: repository/tag/asset/signature/hash must match')
    if set(actual) != set(wanted):
        raise ValueError('Unexpected updater metadata fields')
    datetime.fromisoformat(actual['pub_date'].replace('Z', '+00:00'))
    return [directory / name for name in sorted(expected)]


def publish(directory, tag):
    assets = validate(directory, tag)
    def gh(*args):
        return subprocess.run(['gh', *args], check=True, text=True, capture_output=True).stdout
    # Never allow gh's default repository (the private source repo).
    if json.loads(gh('repo', 'view', REPOSITORY, '--json', 'visibility'))['visibility'] != 'PUBLIC':
        raise ValueError('Updates repository must already exist and be PUBLIC')
    listing = json.loads(gh('release', 'list', '--repo', REPOSITORY, '--limit', '1000', '--json', 'tagName,isDraft'))
    existing = next((item for item in listing if item['tagName'] == tag), None)
    if existing and not existing['isDraft']:
        raise ValueError('Refusing to overwrite an already published release')
    if not existing:
        gh('release', 'create', tag, '--repo', REPOSITORY, '--draft', '--title', tag,
           '--notes', 'macOS arm64. Ad-hoc code signature; no Apple notarization. Signed Tauri updater assets only.')
    # Failed uploads leave the release a draft. Retries cannot expose partial latest.json.
    gh('release', 'upload', tag, '--repo', REPOSITORY, '--clobber', *map(str, assets))
    remote = json.loads(gh('release', 'view', tag, '--repo', REPOSITORY, '--json', 'assets'))['assets']
    if {item['name'] for item in remote} != {file.name for file in assets}:
        raise ValueError('Remote draft contains missing or extra assets; refusing to publish')
    sizes = {item['name']: item['size'] for item in remote}
    if sizes != {file.name: file.stat().st_size for file in assets}:
        raise ValueError('Remote asset sizes differ; refusing to publish')
    # Re-read immediately before promotion; workflow serializes all release versions.
    listing = json.loads(gh('release', 'list', '--repo', REPOSITORY, '--limit', '1000', '--json', 'tagName,isDraft'))
    current = tuple(map(int, version(tag).split('.')))
    newer = any(not item['isDraft'] and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item['tagName']) and
                tuple(map(int, item['tagName'][1:].split('.'))) > current for item in listing)
    gh('release', 'edit', tag, '--repo', REPOSITORY, '--draft=false', '--latest=false' if newer else '--latest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['config', 'check-app', 'prepare', 'check', 'publish'])
    parser.add_argument('--tag')
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--signature', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.command == 'config':
        print(json.dumps(native_config(root)))
    elif args.command == 'check-app':
        check_app(args.app)
    else:
        version(args.tag or '')
        if args.directory is None:
            parser.error('--directory is required')
        if args.command == 'prepare':
            # Fresh output only; never delete someone else's source or old artifacts.
            args.directory.mkdir(parents=True, exist_ok=False)
            archive_check(args.archive)
            signature(args.signature)
            import shutil
            shutil.copyfile(args.archive, args.directory / asset_name(args.tag))
            shutil.copyfile(args.signature, args.directory / (asset_name(args.tag) + '.sig'))
            (args.directory / 'latest.json').write_text(json.dumps(metadata(args.directory, args.tag), indent=2) + '\n')
        if args.command == 'publish':
            publish(args.directory.resolve(), args.tag)
        else:
            validate(args.directory, args.tag)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        # Do not echo gh stderr, command environment or signing material.
        print(f'Release check failed: {error}', file=sys.stderr)
        sys.exit(1)
