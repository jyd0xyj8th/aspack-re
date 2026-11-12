#!/usr/bin/env python3
"""Section walker for ASPack 2.12-wrapped PE files.

Dumps the section table, per-section entropy, the entry point, and the file
offsets of stub markers, so the Ghidra scripts in scripts/ can be aimed at
real offsets instead of guesswork.

Only PE32 (0x10b) images are interpreted; PE32+ is parsed but marks the
optional header fields as unavailable.
"""

import argparse
import json
import math
import struct
import sys
from pathlib import Path

DOS = struct.Struct("<2s58sI")
COFF = struct.Struct("<HHIIIHH")
SECTION = struct.Struct("<8sIIIIIIHHI")

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_UNINIT = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

MARKERS = (b"ASPack", b"aPLib", b".aspack", b".adata", b"ASPack2.12")


class PEError(Exception):
    pass


def section_name(raw):
    return raw.split(b"\0", 1)[0].decode("latin-1", "replace")


def entropy(blob):
    if not blob:
        return 0.0
    counts = [0] * 256
    for byte in blob:
        counts[byte] += 1
    total = float(len(blob))
    return -sum((c / total) * math.log(c / total, 2) for c in counts if c)


def flags_text(flags):
    marks = []
    if flags & IMAGE_SCN_CNT_CODE:
        marks.append("code")
    if flags & IMAGE_SCN_CNT_UNINIT:
        marks.append("bss")
    if flags & IMAGE_SCN_MEM_EXECUTE:
        marks.append("x")
    if flags & IMAGE_SCN_MEM_WRITE:
        marks.append("w")
    return ",".join(marks) or "-"


def parse(path):
    raw = path.read_bytes()
    if len(raw) < DOS.size:
        raise PEError("truncated DOS header")

    magic, _, e_lfanew = DOS.unpack_from(raw, 0)
    if magic != b"MZ":
        raise PEError("no MZ signature")
    if e_lfanew + 4 + COFF.size > len(raw):
        raise PEError("e_lfanew 0x%x outside file" % e_lfanew)
    if raw[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise PEError("no PE signature at 0x%x" % e_lfanew)

    coff_off = e_lfanew + 4
    machine, nsect, _, _, _, optsize, chars = COFF.unpack_from(raw, coff_off)
    opt_off = coff_off + COFF.size
    if optsize < 2 or opt_off + optsize > len(raw):
        raise PEError("optional header size %d does not fit" % optsize)

    opt_magic = struct.unpack_from("<H", raw, opt_off)[0]
    entry_rva = struct.unpack_from("<I", raw, opt_off + 16)[0] if optsize >= 20 else None

    sect_off = opt_off + optsize
    sections = []
    for index in range(nsect):
        off = sect_off + index * SECTION.size
        if off + SECTION.size > len(raw):
            raise PEError("section %d header outside file" % index)
        name, vsize, vaddr, rawsize, rawptr, _, _, _, _, flags = SECTION.unpack_from(raw, off)
        body = raw[rawptr:rawptr + rawsize] if rawptr and rawsize else b""
        sections.append({
            "index": index,
            "name": section_name(name),
            "virtual_address": vaddr,
            "virtual_size": vsize,
            "raw_size": rawsize,
            "raw_pointer": rawptr,
            "entropy": round(entropy(body), 4),
            "flags": flags_text(flags),
        })

    markers = []
    for marker in MARKERS:
        start = 0
        while True:
            found = raw.find(marker, start)
            if found < 0:
                break
            markers.append({"marker": marker.decode("latin-1"), "offset": found})
            start = found + 1

    return {
        "file": str(path),
        "size": len(raw),
        "machine": machine,
        "characteristics": chars,
        "entry_rva": entry_rva,
        "optional_magic": opt_magic,
        "pe_offset": e_lfanew,
        "sections": sections,
        "markers": markers,
    }


def render(info):
    out = []
    out.append("%s  size=%d  e_lfanew=0x%x  machine=0x%04x"
               % (info["file"], info["size"], info["pe_offset"], info["machine"]))
    if info["entry_rva"] is not None:
        out.append("entry RVA 0x%x" % info["entry_rva"])
    out.append("")
    out.append("idx  name       vaddr      vsize      rawptr     rawsize    H      flags")
    for s in info["sections"]:
        out.append("%3d  %-9s  0x%08x 0x%08x 0x%08x 0x%08x  %5.2f  %s"
                   % (s["index"], s["name"], s["virtual_address"], s["virtual_size"],
                      s["raw_pointer"], s["raw_size"], s["entropy"], s["flags"]))
    if info["markers"]:
        out.append("")
        out.append("stub markers")
        for m in info["markers"]:
            out.append("  0x%08x  %s" % (m["offset"], m["marker"]))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="walk PE sections and ASPack stub markers")
    ap.add_argument("sample", type=Path)
    ap.add_argument("--json", action="store_true", help="emit parsed data as JSON")
    args = ap.parse_args(argv)

    try:
        info = parse(args.sample)
    except (OSError, PEError) as exc:
        print("pewalk: %s" % exc, file=sys.stderr)
        return 1

    print(json.dumps(info, indent=2) if args.json else render(info))
    return 0


if __name__ == "__main__":
    sys.exit(main())
