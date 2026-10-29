#!/bin/sh
# Builds the release archives with zig for every target into OUTDIR:
#   geneva-VERSION-linux-ARCH.tar.gz   static musl binary + docs + packaging/
#   geneva-VERSION-windows-ARCH.zip    geneva.exe (+ WinDivert from WINDIVERT_DIR)
#   SHA256SUMS
#
#   tools/build-release.sh [--test] VERSION OUTDIR [TARGET...]
#
# --test also builds and runs the unit tests of every Linux target (with
# qemu-user through binfmt for foreign architectures). WINDIVERT_DIR is the
# unpacked official WinDivert release (WinDivert-X.Y.Z-A); without it the
# Windows archives carry only geneva.exe. Needs zig 0.14, make, tar, zip.
set -eu

TEST=0
if [ "${1:-}" = "--test" ]; then TEST=1; shift; fi
VERSION=${1:?version}
OUT=$(mkdir -p "${2:?outdir}" && cd "$2" && pwd)
shift 2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
JOBS=$(nproc 2>/dev/null || echo 4)

# name|zig target and CPU|os
# (mips64: zig itself passes -fno-PIC for a static build, which clang
# ignores under the N64 ABI with a warning that -Werror would turn fatal)
ALL="
linux-x86_64|-target x86_64-linux-musl|posix
linux-x86|-target x86-linux-musl -mcpu=i686|posix
linux-aarch64|-target aarch64-linux-musl|posix
linux-armv7|-target arm-linux-musleabihf -mcpu=generic+v7a|posix
linux-armv6|-target arm-linux-musleabihf -mcpu=arm1176jzf_s|posix
linux-armv5|-target arm-linux-musleabi -mcpu=arm926ej_s|posix
linux-mips|-target mips-linux-musleabi -mcpu=mips32+soft_float|posix
linux-mipsel|-target mipsel-linux-musleabi -mcpu=mips32+soft_float|posix
linux-mips64|-target mips64-linux-muslabi64 -Wno-option-ignored|posix
linux-riscv64|-target riscv64-linux-musl|posix
linux-ppc|-target powerpc-linux-musleabi|posix
windows-x86_64|-target x86_64-windows-gnu|windows
windows-x86|-target x86-windows-gnu -mcpu=i686|windows
windows-arm64|-target aarch64-windows-gnu|windows
"

# want NAME [TARGET...]: no targets means all
want() {
    n=$1
    shift
    [ $# -eq 0 ] && return 0
    for t in "$@"; do [ "$t" = "$n" ] && return 0; done
    return 1
}

cd "$ROOT"
: > "$OUT/build.log"
echo "$ALL" | while IFS='|' read -r name flags os; do
    [ -n "$name" ] || continue
    want "$name" "$@" || continue
    O="$OUT/obj/$name"
    rm -rf "$O"
    echo "== $name"
    make -s -j"$JOBS" O="$O" CC="zig cc $flags" AR="zig ar" OS_TARGET="$os" STATIC=1 SMALL=1 \
        VERSION="$VERSION" CFLAGS="-Werror" LDFLAGS="-s" >> "$OUT/build.log" 2>&1 ||
        { tail -30 "$OUT/build.log"; exit 1; }
    pkg="geneva-$VERSION-$name"
    stage="$OUT/stage/$pkg"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp README.md README.en.md LICENSE "$stage/"
    if [ "$os" = windows ]; then
        cp "$O/geneva.exe" "$stage/"
        arch=${name#windows-}
        if [ -n "${WINDIVERT_DIR:-}" ] && [ "$arch" != arm64 ]; then
            # WinDivert has no ARM64 driver: the engine needs x64 or x86
            sub=$([ "$arch" = x86_64 ] && echo x64 || echo x86)
            cp "$WINDIVERT_DIR/$sub/WinDivert.dll" "$WINDIVERT_DIR/$sub/"WinDivert*.sys "$stage/"
            cp "$WINDIVERT_DIR/LICENSE" "$stage/WinDivert-LICENSE.txt"
        fi
        (cd "$OUT/stage" && rm -f "$OUT/$pkg.zip" && zip -qr "$OUT/$pkg.zip" "$pkg")
    else
        cp "$O/geneva" "$stage/"
        cp -r packaging "$stage/"
        tar -C "$OUT/stage" -czf "$OUT/$pkg.tar.gz" "$pkg"
        if [ $TEST -eq 1 ]; then
            echo "   unit tests"
            make -s -j"$JOBS" O="$O" CC="zig cc $flags" AR="zig ar" OS_TARGET="$os" STATIC=1 SMALL=1 \
                VERSION="$VERSION" CFLAGS="-Werror" "$O/geneva-tests" >> "$OUT/build.log" 2>&1 ||
                { tail -30 "$OUT/build.log"; exit 1; }
            "$O/geneva-tests" > "$OUT/test-$name.log" 2>&1 || { tail -40 "$OUT/test-$name.log"; exit 1; }
            tail -1 "$OUT/test-$name.log"
        fi
    fi
    ls -l "$O"/geneva* | awk '{print "   " $5 " bytes  " $NF}' | grep -v tests
done
rm -rf "$OUT/stage"
cd "$OUT"
sha256sum geneva-*.tar.gz geneva-*.zip 2>/dev/null > SHA256SUMS
cat SHA256SUMS
