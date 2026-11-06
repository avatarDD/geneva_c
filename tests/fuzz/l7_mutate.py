#!/usr/bin/env python3
"""Mutated copies of seed files for tests/fuzz/l7_diff.sh:
l7_mutate.py OUTDIR COUNT SEED FILE..."""
import os
import random
import struct
import sys


def mutate(r, d, seeds):
    d = bytearray(d)
    for _ in range(r.randint(1, 4)):
        k = r.randrange(9)
        n = len(d)
        if k == 0 and n:
            del d[r.randrange(n):]
        elif k == 1 and n:
            i = r.randrange(n)
            d[i] ^= 1 << r.randrange(8)
        elif k == 2 and n:
            d[r.randrange(n)] = r.choice([0, 1, 2, 3, 5, 6, 0x16, 0x7f, 0x80, 0xc0, 0xfe, 0xff])
        elif k == 3 and n >= 2:
            # a length field: something near the size or huge
            i = r.randrange(n - 1)
            v = r.choice([0, 1, n - i, n - i - 2, n, n + 1, 0x4000, 0xffff, r.randrange(0x10000)]) & 0xffff
            d[i:i + 2] = struct.pack('>H', v)
        elif k == 4 and n:
            i = r.randrange(n)
            d[i:i] = bytes(r.randrange(256) for _ in range(r.randint(1, 8)))
        elif k == 5 and n:
            i = r.randrange(n)
            del d[i:i + r.randint(1, 8)]
        elif k == 6:
            o = seeds[r.randrange(len(seeds))]
            if o:
                i = r.randrange(len(o))
                d[r.randrange(n + 1):] = o[i:]
        elif k == 7 and n:
            i = r.randrange(n)
            d[i:i + 4] = r.choice([b'Host', b'\nHos', b'GET ', b'\r\n\r\n', b'\x00\x00', b'\xff\xff\xff\xff'])
        elif k == 8 and n > 4:
            # a 24-bit (handshake) or varint-looking length
            i = r.randrange(n - 3)
            d[i:i + 3] = (r.randrange(1 << 24)).to_bytes(3, 'big')
    return bytes(d[:65535])


def main():
    out, count, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    seeds = [open(f, 'rb').read() for f in sys.argv[4:]]
    r = random.Random(seed)
    for i in range(count):
        with open(os.path.join(out, '%06d.bin' % i), 'wb') as f:
            f.write(mutate(r, seeds[r.randrange(len(seeds))], seeds))


main()
