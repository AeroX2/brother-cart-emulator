"""Brother embroidery card image generator.

Turns a set of .pes designs into a card image, reproducing what PED-Basic's
CardIO.dll writes. Reverse engineered from PED-Basic 1.07 / CardIO.dll 3.2.1.1;
see NOTES.md for where each rule comes from.

Two halves:

  stage 1  .pes  ->  pattern inputs (stitch stream, thumbnails, block count)
  stage 2  inputs -> card image     (header, pointer tables, data section)

Usage:
    python cardgen.py --selftest              verify against the reference card
    python cardgen.py a.pes b.pes -o card.bin build a card image

Verified byte-for-byte: `--selftest` pulls the generator's own inputs back out of
a known-good card image, regenerates all 521,024 bytes, and requires an exact
match.

Caveats before flashing:
  * verified against exactly ONE reference card (hoop 0, 512 KiB, 3 patterns);
    other hoop sizes need their own glyph block, which is not included here
  * a single-colour design has block_count 0, so its attribute byte is written
    as 0xFF; that follows the decompiled code but has not been seen in a real
    PED-Basic card
  * no generated card has been run on a sewing machine
"""
import os
import struct
import sys

BIAS = 0x400000
REC = 0xE4                      # thumbnail / block record size
MASK_TAG = 0xF0                 # 5-byte mask header: tag, width LE16, height LE16

# The glyph/font block PED-Basic writes into every card. It is static data
# (largely copied verbatim out of CardIO.dll's .data) and does not depend on the
# designs, but it IS hoop-dependent, so it is lifted from a reference image.
TEMPLATE_LO = 0x1100
TEMPLATE_HI = 0x191E8           # == C0, where the pattern data section starts

DEFAULT_REF = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "code-esp32", "data", "image.bin")


def u24(d, i):
    return d[i] | (d[i + 1] << 8) | (d[i + 2] << 16)


def put3(buf, off, val):
    buf[off] = val & 0xFF
    buf[off + 1] = (val >> 8) & 0xFF
    buf[off + 2] = (val >> 16) & 0xFF


class Pattern:
    """The CMExeEmb fields the card serializer consumes."""

    def __init__(self, sew, thumbs, block_count):
        self.sew = bytes(sew)             # mask header + PEC stitch stream
        self.thumbs = [bytes(t) for t in thumbs]   # 1 + block_count records
        self.block_count = block_count    # == colour changes

    @property
    def kind(self):
        """1 for multi-block patterns; drives the interleave stride."""
        return 0 if self.block_count == 1 else 1


# --------------------------------------------------------------- stage 1 --

def mask_header(buf):
    """GetMaskData: returns (stitch_start, width, height)."""
    b = buf[0]
    if b == 0xF0:
        return 5, buf[1] | (buf[2] << 8), buf[3] | (buf[4] << 8)
    if b == 0xF1:
        w = h = 0
        i = 1
        for _ in range(4):
            w += buf[i] | (buf[i + 1] << 8)
            h += buf[i + 2] | (buf[i + 3] << 8)
            i += 4
        return i, w, h
    if b < 0x80:
        return 2, b, buf[1]
    return 6, (b & 0x7F) + buf[2] + buf[4], (buf[1] & 0x7F) + buf[3] + buf[5]


def pattern_from_pes(data):
    """stage 1: parse a .pes into a Pattern.

    The card stores the PEC stitch stream verbatim behind a 5-byte mask header,
    and the PEC 48x38 thumbnails verbatim as the 0xE4 records.
    """
    import pescheck

    if data[:4] != b"#PES":
        raise ValueError("not a PES file")
    pec = struct.unpack_from("<I", data, 8)[0]
    if not 0 < pec < len(data):
        raise ValueError("PEC offset out of range")

    changes = data[pec + 0x30]
    body = pec + 0x200

    found = pescheck.find_stitch_start(data, pec, changes)
    if not found:
        raise ValueError("no valid stitch stream (PED-Basic would reject this)")
    start, walked = found
    if not walked["parity_ok"]:
        raise ValueError("colour-change parity is wrong; repair with pescheck --fix")

    stream = data[start:walked["at"] + 1]          # include the 0xFF terminator
    w = walked["bbox"][2] - walked["bbox"][0]
    h = walked["bbox"][3] - walked["bbox"][1]
    sew = bytes([MASK_TAG, w & 0xFF, w >> 8, h & 0xFF, h >> 8]) + stream

    graphics = body + u24(data, body + 2)
    thumbs = [data[graphics + i * REC: graphics + (i + 1) * REC]
              for i in range(changes + 1)]
    if any(len(t) != REC for t in thumbs):
        raise ValueError("thumbnail block runs past the end of the file")

    return Pattern(sew, thumbs, changes)


# --------------------------------------------------------------- stage 2 --

def build_card(patterns, reference, card_bytes=0x80000):
    """stage 2: lay the patterns out into a complete card image."""
    ref = bytes(reference)
    n = len(patterns)
    buf = bytearray(b"\xFF" * card_bytes)

    # Static glyph/font block and the header text (both taken from the
    # reference: the text comes from pelite's version resource, the block is
    # constant data PED-Basic emits for this hoop).
    buf[TEMPLATE_LO:TEMPLATE_HI] = ref[TEMPLATE_LO:TEMPLATE_HI]

    # ---- FUN_10006B11 : header -------------------------------------------
    buf[0x00:0x55] = ref[0x00:0x55]        # copyright line
    buf[0xA0] = 0
    buf[0xB7] = 0xF1
    buf[0xD0:0xE0] = ref[0xD0:0xE0]        # trademark (strncpy 16, unterminated)
    buf[0xE0:0xF0] = ref[0xE0:0xF0]        # file version
    buf[0xF0:0xFF] = ref[0xF0:0xFF]        # date
    buf[0x110] = 0x5E
    struct.pack_into("<H", buf, 0x116, 0xFFFB)
    put3(buf, 0x120, 0x410000)
    put3(buf, 0x128, 0x410004)
    put3(buf, 0x130, 0x410008)
    put3(buf, 0x150, 0)
    put3(buf, 0x153, 0)
    buf[0x156] = 10
    # Hoop-block pointers and the card serial live in the static region.
    buf[0x157:0x18E] = ref[0x157:0x18E]
    buf[0x18E:0x191] = ref[0x18E:0x191]    # card serial (3 random bytes)
    put3(buf, 0xA1, u24(ref, 0xA1))        # -> appended 9-byte block

    # ---- FUN_100071EB : hoop-0 marker -------------------------------------
    buf[0x100] = ord("b")                  # final commit byte
    buf[0x101:0x10E] = b"rother_sewing"

    # ---- FUN_10006E0B : pointer tables + descriptor blocks ----------------
    has_t1 = any(p.kind == 1 for p in patterns)
    has_t0 = any(p.kind == 0 for p in patterns)
    stride = 2 if (has_t1 and has_t0) else 1

    desc = 0x1069
    off = 0x100F
    for i in range(8):
        put3(buf, off, BIAS + desc + i * stride)
        off += 3
    p = desc + 8 * stride
    put3(buf, 0x1033, BIAS + p)
    put3(buf, 0x1036, BIAS + p + stride)
    iv = desc + 10 * stride
    put3(buf, 0x1048, BIAS + iv); iv += stride
    put3(buf, 0x1057, BIAS + iv); iv += stride
    put3(buf, 0x1003, BIAS + iv)
    for k, addr in enumerate((0x1042, 0x1045, 0x1051, 0x1054, 0x105A), start=1):
        put3(buf, addr, BIAS + iv + n * k)

    fixed = [8, 0, 0xA0, 0x67, 0, 1, 0xFF, 0xFF, 0, 0]
    for lane in range(stride):
        c = desc + lane
        for col, val in enumerate(fixed):
            buf[c + col * stride] = val
        buf[c + 10 * stride] = 4 if (lane == 0 and has_t1) else 6
        buf[c + 11 * stride] = 0

    c0 = desc + stride * 12
    for i, pat in enumerate(patterns):
        c = c0 + i
        buf[c + n * 0] = 1 if (stride == 2 and pat.block_count != 1) else 0
        buf[c + n * 1] = 0x32
        buf[c + n * 2] = (pat.block_count - 1) & 0xFF
        buf[c + n * 3] = 0x40
        buf[c + n * 4] = 6
        buf[c + n * 5] = 0

    # ---- FUN_1000908A : data section --------------------------------------
    total = sum(p.block_count for p in patterns)
    multi = sum(p.block_count for p in patterns if p.block_count != 1)
    ones = [i + 1 for i, p in enumerate(patterns) if p.block_count == 1]
    t68 = max(ones) if ones else 0

    C0 = TEMPLATE_HI
    cur24 = C0                                   # per-pattern record pointers
    l38 = C0 + n * 3                             # single-block pointer slots
    l3c = l38 + (t68 * 3 if ones else 0)         # multi-block pointer cursor
    lc = l38 + (multi + t68) * 3                 # stitch-data pointer table
    l1c = lc + n * 3                             # per-pattern records
    l14 = l1c + n * REC                          # per-block records
    l10 = l14 + total * REC                      # stitch payloads

    put3(buf, 0x42A2, BIAS + l38)                # hoop 0 slot
    put3(buf, 0x1000, BIAS + lc)

    for pat in patterns:
        put3(buf, cur24, BIAS + l1c)
        cur24 += 3
        buf[l1c:l1c + REC] = pat.thumbs[0]
        l1c += REC

        for j in range(pat.block_count):
            if pat.block_count == 1:
                put3(buf, l38, BIAS + l14)
            else:
                put3(buf, l3c, BIAS + l14 + j * REC)
                l3c += 3
        l38 += 3

        for k in range(1, pat.block_count + 1):
            buf[l14:l14 + REC] = pat.thumbs[k]
            l14 += REC

        put3(buf, lc, BIAS + l10)
        lc += 3
        buf[l10:l10 + 4] = b"\x00\x00\x00\x00"
        l10 += 4
        buf[l10:l10 + len(pat.sew)] = pat.sew
        l10 += len(pat.sew)

    if l10 > card_bytes:
        raise ValueError("designs do not fit on a %d byte card" % card_bytes)
    return bytes(buf), l10


# ------------------------------------------------------- verification ----

def patterns_from_image(ref):
    """Pull the generator's own inputs back out of a finished card image."""
    n = u24(ref, 0x1042) - u24(ref, 0x1003)
    base = u24(ref, 0x1003) - BIAS
    # The column stores block_count - 1, so a single-colour design (no colour
    # changes, block_count 0) is written as 0xFF. Wrap rather than overflow.
    counts = [(ref[base + 2 * n + i] + 1) & 0xFF for i in range(n)]

    total = sum(counts)
    multi = sum(c for c in counts if c != 1)
    ones = [i + 1 for i, c in enumerate(counts) if c == 1]
    t68 = max(ones) if ones else 0

    lc = u24(ref, 0x1000) - BIAS
    l1c = lc + n * 3
    l14 = l1c + n * REC
    l10 = l14 + total * REC

    starts = [u24(ref, lc + i * 3) - BIAS for i in range(n)]
    used = len(ref.rstrip(b"\xFF")) + 1
    ends = starts[1:] + [used]

    patterns = []
    blk = l14
    for i, cnt in enumerate(counts):
        sew = ref[starts[i] + 4:ends[i]]
        thumbs = [ref[l1c + i * REC: l1c + (i + 1) * REC]]
        for _ in range(cnt):
            thumbs.append(ref[blk:blk + REC])
            blk += REC
        patterns.append(Pattern(sew, thumbs, cnt))
    return patterns


def selftest(ref_path=DEFAULT_REF):
    ref = open(ref_path, "rb").read()
    patterns = patterns_from_image(ref)
    print("reference: %s" % os.path.normpath(ref_path))
    print("recovered %d patterns, block counts %s"
          % (len(patterns), [p.block_count for p in patterns]))
    for i, p in enumerate(patterns):
        start, w, h = mask_header(p.sew)
        print("  pattern %d: %d stitch bytes, %d thumbnails, %.1f x %.1f mm"
              % (i, len(p.sew), len(p.thumbs), w / 10, h / 10))

    out, end = build_card(patterns, ref, card_bytes=len(ref))
    diffs = [i for i in range(len(ref)) if out[i] != ref[i]]
    print("\nregenerated %d bytes, data ends at 0x%X" % (len(out), end))
    if diffs:
        print("FAIL: %d bytes differ; first at 0x%05X (mine %02X, ref %02X)"
              % (len(diffs), diffs[0], out[diffs[0]], ref[diffs[0]]))
        for i in diffs[:10]:
            print("   0x%05X: mine %02X  ref %02X" % (i, out[i], ref[i]))
        return False
    print("PASS: regenerated card is byte-for-byte identical to the reference")
    return True


def main(argv):
    if "--selftest" in argv or len(argv) == 1:
        return 0 if selftest() else 1

    out_path = "image.bin"
    if "-o" in argv:
        out_path = argv[argv.index("-o") + 1]
    pes_paths = [a for a in argv[1:]
                 if a.lower().endswith(".pes") and os.path.exists(a)]
    if not pes_paths:
        print(__doc__)
        return 1

    ref = open(DEFAULT_REF, "rb").read()
    patterns = []
    for path in pes_paths:
        pat = pattern_from_pes(open(path, "rb").read())
        start, w, h = mask_header(pat.sew)
        print("%-44s %2d blocks  %.1f x %.1f mm"
              % (os.path.basename(path), pat.block_count, w / 10, h / 10))
        patterns.append(pat)

    out, end = build_card(patterns, ref)
    with open(out_path, "wb") as fh:
        fh.write(out)
    print("\nwrote %s (%d bytes, %d used)" % (out_path, len(out), end))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
