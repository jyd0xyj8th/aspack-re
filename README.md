# aspack-re

Small tooling and notes for triaging 32-bit PE files wrapped by the ASPack
2.12 runtime stub. The packer itself is old and boring; what matters is
reaching the original entry point (OEP) without losing an afternoon to the
section table.

Two pieces do the mechanical part:

- `pewalk.py` reads the section table without loading the image and reports
  entropy, section flags, the entry RVA, and the file offsets of the stub
  markers (`ASPack`, `aPLib`, `.aspack`).
- `scripts/find_oep.py` runs inside Ghidra, walks the stub from the entry
  point, and resolves the tail `jmp` to a candidate OEP. `scripts/dump_iat.py`
  lists call sites that still point into the EXTERNAL block after unpacking,
  so the import table can be rebuilt by hand.

The scripts report; they never patch the program. That keeps the original
bytes intact for a second opinion.

## Why ASPack 2.12

It is still glued onto old malware samples by packer wrappers, and the stub
is regular enough to describe. A 2.12 stub has three landmarks: a `pushad`
that saves the register file, the decompression loop, and a `popad`
immediately before the transfer to OEP. Finding the transfer is a two-minute
job once the layout is known, and doing it by hand is the part that eats the
afternoon on a sample with a corrupted section table.

## Layout

The DOS header points at the PE header, and the section table sits after the
optional header:

```
00000000  4d 5a 90 00 03 00 00 00  00 00 00 00 00 00 00 00  |MZ..............|
0000003c  80 00 00 00                                       |.e_lfanew = 0x80|
00000080  50 45 00 00 4c 01 03 00  00 00 00 00 00 00 00 00  |PE..L...........|
```

ASPack keeps a writable, high-entropy section for the compressed payload and
a small executable section for the stub. A typical table entry:

```
00000300  2e 61 73 70 61 63 6b ff  ff ff ff 00 30 00 00        |.aspack.....0..|
00000310  00 60 00 00 00 08 00 00  00 00 00 00 00 00 00 00  |.`..............|
00000320  00 00 00 00 20 00 00 e0                           |....   .........|
```

| field            | meaning                                  |
|------------------|------------------------------------------|
| `Name`           | `.aspack`, `.adata`, sometimes padded     |
| `VirtualSize`    | decompressed size, often larger than raw  |
| `PointerToRawData` | file offset of the compressed payload   |
| `Characteristics` | `0xE0000020`: code, execute, read, write |

The tail of the stub looks like this, with `relative` targeting the first
byte of the last section:

```
60                      pushad
e8 ........              call decompressor
61                      popad
e9 ........              jmp OEP
```

`find_oep.py` matches exactly that `60` ... `61` ... `e9`/`eb` sequence and
resolves the displacement from the end of the jump.

## Install

No third-party modules for `pewalk.py`; it needs Python 3.8 or newer.

```sh
git clone https://github.com/jyd0xyj8th/aspack-re
cd aspack-re
```

For the Ghidra side, copy `scripts/` into your user script directory:

```sh
cp -r scripts ~/.ghidra/ghidra_scripts/aspack-re
```

and refresh the Script Manager. Tested on Ghidra 11.x with the default
`x86:LE:32:default` language.

## Usage

```sh
python3 pewalk.py sample.exe
python3 pewalk.py sample.exe --json > table.json
```

In Ghidra's Script Manager, with the sample loaded at its preferred base:

1. Run `find_oep.py` to get the candidate offset.
2. Run `verify/verify_oep.py` with that offset (see `verify/README.md`).
3. Run `dump_iat.py` after the dump, then fix the listed call sites.

Then rebuild the section table entry and set the entry point. Keep a copy of
the untouched file; the packer's section names are the tell that a later
sample came from the same wrapper.

## Files

```
pewalk.py            section table and stub marker walker
scripts/find_oep.py  Ghidra: resolve the tail jump
scripts/dump_iat.py  Ghidra: list unresolved external call sites
verify/              candidate scoring for the OEP
```

## Limits

- 32-bit x86 only; there is no 2.12 stub for other targets this tooling
  understands.
- ASPack versions differ in the stub prologue. 2.11 and earlier use
  `pushfd`/`pushad` in the other order, so the match fails cleanly.
- A candidate OEP is a hint, not proof. Entropy stops being a signal on
  samples with an encrypted overlay.

MIT licensed, see `LICENSE`.
