#!/usr/bin/env python3
"""Build arm64 JNI without changing the installed Rust sysroot."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = '1.95.0'
TARGET = 'aarch64-linux-android'
ARCHIVE = f'rust-std-{VERSION}-{TARGET}'
SHA256 = 'de5e8fa5d955809891eea77682811fc90be705f78883bd94071e98f5a738d05b'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--toolchain', type=Path, required=True, help='Existing Rust 1.95.0 toolchain directory (read only)')
p.add_argument('--ndk', type=Path, required=True, help='Android NDK directory (Linux x86_64 host)')
p.add_argument('--build-dir', type=Path, default=ROOT / 'build' / 'android-core')
a = p.parse_args()
rustc = a.toolchain.resolve() / 'bin' / 'rustc'
if not subprocess.check_output([rustc, '--version'], text=True).startswith(f'rustc {VERSION} '):
    p.error(f'--toolchain must contain Rust {VERSION}')
linker = a.ndk.resolve() / 'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang'
if not linker.is_file():
    p.error('NDK arm64 API 33 linker missing')
build = a.build_dir.resolve()
build.mkdir(parents=True, exist_ok=True)
archive = build / f'{ARCHIVE}.tar.xz'
def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
if not archive.exists():
    partial = archive.with_suffix('.partial')
    try:
        with urllib.request.urlopen(f'https://static.rust-lang.org/dist/{archive.name}', timeout=60) as source, partial.open('wb') as dest:
            shutil.copyfileobj(source, dest)
        if digest(partial) != SHA256:
            raise SystemExit('Rust target archive checksum failed')
        partial.replace(archive)
    finally:
        partial.unlink(missing_ok=True)
if digest(archive) != SHA256:
    raise SystemExit('Rust target archive checksum failed; remove cached archive and retry')
sysroot = build / 'sysroot'
marker = sysroot / '.readb-rust-std-sha256'
if not marker.exists() or marker.read_text() != SHA256:
    stage = build / 'extract'
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir()
    try:
        with tarfile.open(archive) as t:
            t.extractall(stage, filter='data')
        library = stage / ARCHIVE / f'rust-std-{TARGET}' / 'lib' / 'rustlib' / TARGET
        destination = sysroot / 'lib' / 'rustlib' / TARGET
        shutil.copytree(library, destination, dirs_exist_ok=True)
        marker.write_text(SHA256)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
env = os.environ.copy()
env.update(RUSTC=str(rustc), CARGO_TARGET_DIR=str(build / 'cargo'),
           CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=str(linker),
           CARGO_ENCODED_RUSTFLAGS='--sysroot\x1f' + str(sysroot) + '\x1f-Clink-arg=-Wl,-z,max-page-size=16384')
env.pop('RUSTFLAGS', None)
subprocess.run(['cargo', 'build', '--locked', '-p', 'readb-android-core', '--release', '--target', TARGET], cwd=ROOT, env=env, check=True)
print(build / 'cargo' / TARGET / 'release' / 'libreadb_android_core.so')
