# Lists for tests/test_lists.c

Made up (no third-party content), generated once with Python's `gzip` and
`zlib` (level 9, so the blocks are dynamic Huffman):

- `hosts.txt` — CRLF lines: comments (`#`, `;`, `/`), an empty line,
  leading spaces and tabs, `^strict.org`, `!good.example.com`, an upper
  case name with trailing words, and 3000 names `hNNNN-xxxxxx.test`;
- `hosts.txt.gz` — the same in gzip (with a file name in the header);
- `hosts.txt.z` — the same in zlib;
- `ips.txt`, `ips.txt.gz` — an IP set with two bad entries.
