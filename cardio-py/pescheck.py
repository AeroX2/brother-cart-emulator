"""Check a .pes file against PED-Basic's own stitch validator.

    python pescheck.py design.pes [more.pes ...]

This is a faithful port of `CMExeEmb::ChkPesFormat` from PeCommon.dll (PED-Basic
1.07). That function walks the PEC stitch stream one opcode at a time and
returns 0 -- "this file cannot be written to a card" -- the moment it meets
anything it does not recognise. Running the same walk here tells you whether
PED-Basic will accept a design before you go near the GUI.

Note that CardIO.dll is *not* involved in this. It never parses PES; it receives
an already-decoded object and copies the stitch block verbatim. All format
validation happens in PeCommon.dll, which is what this reproduces.

No dependencies. Read-only.
"""

import glob
import struct
import sys

# Opcode set accepted by ChkPesFormat. Anything else makes it return 0.
#
#   0x00-0x70 (high nibble)  short stitch, one signed 7-bit delta per axis
#   0x80      (high nibble)  long stitch, one signed 12-bit big-endian per axis
#   0x90,0xA0 (high nibble)  long move/jump, two signed 12-bit big-endian deltas
#   0xB0      (exact)        colour change, plus one operand byte
#   0xC0,0xE0,0xE2 (exact)   two-byte command
#   0xFE      (exact)        one-byte command (precedes 0xB0 in real files)
#   0xFF      (exact)        end of stitches

# Machine generations, as ChkPesFormat's first argument. Sizes are 0.1 mm.
# The last column marks the two generations whose checks retry with width and
# height swapped, i.e. they accept a design in either orientation.
MACHINES = [
    #  name,        max w, max h, max colours, rotatable
    ("D3",           1000,  1000,  0x40, False),
    ("D4",           1300,  1800,  0x40, False),
    ("D5",           1600,  2600,   100, False),
    ("Sapphire",     3000,  2000,  0x80, True),
    ("D6",           1800,  3000,   100, True),
]


def fits(w, h, mw, mh, rotatable):
    if w <= mw and h <= mh:
        return True
    return rotatable and h <= mw and w <= mh


def s12(word):
    """Sign-extend a 12-bit value held in a big-endian word."""
    v = word & 0xFFF
    return v - 0x1000 if v & 0x800 else v


def s7(byte):
    """Sign-extend the 7-bit delta form (bit 6 is the sign)."""
    v = byte & 0x7F
    return v - 0x80 if byte & 0x40 else v


def be16(data, i):
    return struct.unpack_from(">H", data, i)[0]


def walk(data, start):
    """Replay ChkPesFormat's opcode loop. Returns a result dict."""
    i = start
    x = y = 0
    minx = maxx = miny = maxy = 0
    colour_changes = 0
    parity_ok = True
    opcodes = {}
    stitches = 0
    cc_positions = []   # file offsets of each colour-change operand byte

    def note(name):
        opcodes[name] = opcodes.get(name, 0) + 1

    while True:
        if i >= len(data):
            return {"ok": False, "why": "ran off the end of the file at 0x%X" % i,
                    "at": i, "opcodes": opcodes}

        b = data[i]
        hi = b & 0xF0

        if hi >= 0x90:
            if hi in (0x90, 0xA0):
                if i + 4 > len(data):
                    return {"ok": False, "why": "truncated long move", "at": i,
                            "opcodes": opcodes}
                x += s12(be16(data, i))
                y += s12(be16(data, i + 2))
                i += 4
                note("jump 0x%02X" % hi)
                stitches += 1
            elif b == 0xB0:
                operand = data[i + 1]
                cc_positions.append(i + 1)
                i += 2
                colour_changes += 1
                # The validator demands the operand's low bit alternate with the
                # colour-change count -- real files emit 01, 02, 01, 02, ...
                if (colour_changes & 1) != (operand & 1):
                    parity_ok = False
                note("colour change 0xB0")
                continue
            elif b in (0xC0, 0xE0, 0xE2):
                i += 2
                note("cmd 0x%02X" % b)
                continue
            elif b == 0xFE:
                i += 1
                note("0xFE")
                continue
            elif b == 0xFF:
                note("end 0xFF")
                return {"ok": True, "at": i, "opcodes": opcodes,
                        "colour_changes": colour_changes, "parity_ok": parity_ok,
                        "stitches": stitches, "cc_positions": cc_positions,
                        "bbox": (minx, miny, maxx, maxy)}
            else:
                return {"ok": False,
                        "why": "illegal opcode 0x%02X" % b, "at": i,
                        "opcodes": opcodes}
        else:
            # Short/long stitch: one delta per axis, each independently encoded.
            for _ in range(2):
                if i >= len(data):
                    return {"ok": False, "why": "truncated stitch", "at": i,
                            "opcodes": opcodes}
                bb = data[i]
                if (bb & 0xF0) < 0x71:
                    delta = s7(bb)
                    i += 1
                else:
                    delta = s12(be16(data, i))
                    i += 2
                if _ == 0:
                    x += delta
                else:
                    y += delta
            note("stitch")
            stitches += 1

        minx, maxx = min(minx, x), max(maxx, x)
        miny, maxy = min(miny, y), max(maxy, y)


def find_stitch_start(data, pec_off, expected_changes):
    """The PEC body sits after a 512-byte header; pin the exact start by trying
    each plausible offset and keeping the one that parses cleanly."""
    best = None
    for cand in range(pec_off + 0x200, min(pec_off + 0x230, len(data))):
        r = walk(data, cand)
        if not r.get("ok"):
            continue
        if expected_changes is not None and r["colour_changes"] != expected_changes:
            continue
        if best is None or r["stitches"] > best[1]["stitches"]:
            best = (cand, r)
    return best


def repair_parity(path, data, positions):
    """Re-phase the colour-change alternation to start odd, as PED-Basic wants.

    The operand of `FE B0 xx` is only an alternation marker -- the actual thread
    colour comes from the palette table at the top of the PEC block -- so
    flipping its phase changes no stitches and no colours. Writes a new file and
    never touches the original.
    """
    out = bytearray(data)
    for k, pos in enumerate(positions):
        out[pos] = 1 if k % 2 == 0 else 2
    new_path = path[:-4] + ".fixed.pes" if path.lower().endswith(".pes") \
        else path + ".fixed.pes"
    with open(new_path, "wb") as fh:
        fh.write(out)
    return new_path


def check(path, fix=False):
    data = open(path, "rb").read()
    print("=" * 78)
    print(path)

    if data[:4] != b"#PES":
        print("  not a PES file (magic %r)" % data[:8])
        return
    version = data[:8].decode("latin-1")
    pec_off = struct.unpack_from("<I", data, 8)[0]
    print("  version      : %s" % version)
    if not 0 < pec_off < len(data):
        print("  PEC offset   : 0x%X -- out of range" % pec_off)
        return

    colours = data[pec_off + 0x30] + 1
    palette = list(data[pec_off + 0x31:pec_off + 0x31 + colours])
    print("  PEC offset   : 0x%X" % pec_off)
    print("  colours      : %d  %s" % (colours, palette))

    found = find_stitch_start(data, pec_off, colours - 1)
    if not found:
        found = find_stitch_start(data, pec_off, None)
    if not found:
        print("  RESULT       : no valid stitch stream found -- would be REJECTED")
        return

    start, r = found
    w = r["bbox"][2] - r["bbox"][0]
    h = r["bbox"][3] - r["bbox"][1]
    print("  stitch start : 0x%X" % start)
    print("  stitches     : %d" % r["stitches"])
    print("  colour chg   : %d (parity %s)"
          % (r["colour_changes"], "OK" if r["parity_ok"] else "*** WRONG ***"))
    print("  extent       : %d x %d (0.1mm) = %.1f x %.1f mm" % (w, h, w / 10, h / 10))
    print("  opcodes used : %s"
          % ", ".join("%s x%d" % (k, v) for k, v in sorted(r["opcodes"].items())))

    bad = [c for c in palette if c == 0 or c > 0x41]
    if bad:
        print("  palette      : %s outside 1..65 -- will be clamped to 65" % bad)

    ok_for = [name for name, mw, mh, mc, rot in MACHINES
              if fits(w, h, mw, mh, rot) and colours < mc]
    print("  RESULT       : opcodes ALL LEGAL")
    print("  fits         : %s" % (", ".join(ok_for) if ok_for else
                                   "NOTHING -- too large for every hoop"))
    if not r["parity_ok"]:
        print("  WARNING      : colour-change operands start even (2,1,2,...);")
        print("                 ChkPesFormat wants odd first (1,2,1,...) and")
        print("                 returns 0 otherwise. Re-run with --fix.")
        if fix:
            new_path = repair_parity(path, data, r["cc_positions"])
            print("  FIXED        : wrote %s" % new_path)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    fix = "--fix" in sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    # cmd.exe and PowerShell don't expand wildcards for us, so do it here.
    paths = []
    for arg in args:
        hits = sorted(glob.glob(arg))
        paths.extend(hits if hits else [arg])
    for p in paths:
        check(p, fix=fix)
