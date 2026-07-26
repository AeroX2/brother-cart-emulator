"""Annotate the header of a Brother embroidery card image.

    python cardhdr.py image.bin

Field meanings come from reversing CardIO.dll 3.2.1.1 (see NOTES.md); every
offset below was then checked against a real card image, so this doubles as a
regression check on the map.

No dependencies, and it never writes anything.
"""

import sys

# Card pointers are 3-byte little-endian and biased by this amount.
PTR_BIAS = 0x400000

# The "brother_sewing" marker moves with the hoop size. The leading 'b' is the
# last byte the writer sends, so a dump taken from memory has 0xFF there.
HOOP_MARKERS = {0: 0x100, 1: 0x170, 2: 0xC0, 3: 0x28E, 4: 0x280}

# offset, kind, label. String fields carry an explicit length because the
# trademark is written with strncpy(..., 0x10) and is not NUL-terminated when it
# fills all 16 bytes -- reading past it runs straight into the version field.
FIELDS = [
    (0x000, "str:0x60", "copyright line ('%s' = the trademark below)"),
    (0x0A0, "u8",  "always 00"),
    (0x0A1, "ptr", "-> appended 9-byte block"),
    (0x0B7, "u8",  "always F1"),
    (0x0D0, "str:0x10", "LegalTrademarks, from pelite.exe's version resource"),
    (0x0E0, "str:0x10", "FileVersion, spaces stripped and ',' -> '.'"),
    (0x0F0, "str:0x20", "build date"),
    (0x110, "u8",  "always 5E ('^')"),
    (0x116, "u16", "always FFFB"),
    (0x120, "ptr", "fixed 0x410000"),
    (0x128, "ptr", "fixed 0x410004"),
    (0x130, "ptr", "fixed 0x410008"),
    (0x150, "u24", "zero"),
    (0x153, "u24", "zero"),
    (0x156, "u8",  "always 0A"),
    (0x157, "ptr", "-> hoop block"),
    (0x164, "u8",  "always 00"),
    (0x165, "ptr", "-> hoop block"),
    (0x168, "u8",  "1 when a 'type 1' pattern is present"),
    (0x186, "u8",  "always 00"),
    (0x187, "ptr", "-> hoop block"),
    (0x18A, "u8",  "always 00"),
    (0x18B, "ptr", "-> hoop block"),
    (0x18E, "u24", "card serial: 3 random bytes, written last"),
]

# Pointer table in the 0x1000 block, written by FUN_10006E0B / FUN_1000908A.
TABLE = [
    (0x1000, "-> pattern data section"),
    (0x1003, "-> per-pattern attribute table"),
    (0x1033, "-> slot 8"),
    (0x1036, "-> slot 9"),
    (0x1042, "-> attribute column 1"),
    (0x1045, "-> attribute column 2"),
    (0x1048, "-> slot 10"),
    (0x1051, "-> attribute column 3"),
    (0x1054, "-> attribute column 4"),
    (0x1057, "-> slot 11"),
    (0x105A, "-> attribute column 5"),
]


def u24(data, off):
    return data[off] | (data[off + 1] << 8) | (data[off + 2] << 16)


def fmt_ptr(data, off):
    raw = u24(data, off)
    if raw == 0xFFFFFF:
        return "-- unset --"
    return "0x%06X  (image offset 0x%05X)" % (raw, raw - PTR_BIAS)


def cstr(data, off, limit=0x20):
    out = bytearray()
    for b in data[off:off + limit]:
        if b in (0x00, 0xFF):
            break
        out.append(b)
    return out.decode("latin-1")


def main(path):
    data = open(path, "rb").read()
    used = len(data.rstrip(b"\xFF"))
    print("file        : %s" % path)
    print("size        : %d bytes (0x%X)" % (len(data), len(data)))
    print("non-erased  : %d bytes, %d bytes of trailing 0xFF"
          % (used, len(data) - used))
    print()

    # Which hoop layout is this?
    hoop = None
    for index, off in sorted(HOOP_MARKERS.items()):
        if data[off:off + 14] == b"brother_sewing":
            hoop, complete = index, True
            break
        if data[off + 1:off + 14] == b"rother_sewing":
            hoop, complete = index, False
            break
    if hoop is None:
        print("hoop        : no 'brother_sewing' marker found -- not a card image?")
    else:
        print("hoop index  : %d (marker at 0x%03X)" % (hoop, HOOP_MARKERS[hoop]))
        if not complete:
            print("              *** leading 'b' missing -- this dump was taken from")
            print("                  memory before the final commit byte was written")
    print()

    print("--- header ---")
    for off, kind, label in FIELDS:
        if kind.startswith("str:"):
            value = "%r" % cstr(data, off, int(kind[4:], 0))
        elif kind == "u8":
            value = "%02X" % data[off]
        elif kind == "u16":
            value = "%04X" % (data[off] | (data[off + 1] << 8))
        elif kind == "u24":
            value = "%06X" % u24(data, off)
        else:
            value = fmt_ptr(data, off)
        print("  0x%03X  %-38s %s" % (off, value, label))

    print()
    print("--- pointer table ---")
    for off, label in TABLE:
        print("  0x%04X  %-38s %s" % (off, fmt_ptr(data, off), label))

    # The eight-entry table at 0x100F reveals the interleave stride, and the gap
    # between the 0x1003 and 0x1042 pointers is the pattern count.
    first, second = u24(data, 0x100F), u24(data, 0x1012)
    stride = second - first if 0 < second - first < 16 else None
    count = u24(data, 0x1042) - u24(data, 0x1003)
    print()
    print("  slot table at 0x100F, stride %s" % (stride if stride else "?"))
    if stride:
        for i in range(8):
            print("    slot %d  %s" % (i, fmt_ptr(data, 0x100F + i * 3)))
    if 0 < count < 256:
        print()
        print("  pattern count: %d" % count)
        base = u24(data, 0x1003) - PTR_BIAS
        cols = ["kind", "0x32", "blocks-1", "0x40", "0x06", "0x00"]
        print("  attribute table at 0x%05X:" % base)
        for c, name in enumerate(cols):
            row = " ".join("%02X" % data[base + c * count + i] for i in range(count))
            print("    %-9s %s" % (name, row))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
