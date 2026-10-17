#!/bin/sh
# Build with an installed Rust musl target. Never download/accept terms here.
set -eu
if [ "$#" -gt 1 ]; then
    echo 'Usage: build-portable.sh [x86_64-unknown-linux-musl|aarch64-unknown-linux-musl]' >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then
    readb_target=$1
else
    case "$(uname -m)" in
        x86_64) readb_target=x86_64-unknown-linux-musl ;;
        aarch64) readb_target=aarch64-unknown-linux-musl ;;
        *) echo 'Unsupported portable architecture. Supply a verified musl target.' >&2; exit 2 ;;
    esac
fi
case "$readb_target" in
    x86_64-unknown-linux-musl|aarch64-unknown-linux-musl) ;;
    *) echo 'Portable builds require a supported musl target.' >&2; exit 2 ;;
esac
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
exec "${READB_CARGO:-cargo}" build --locked --release --target "$readb_target"
