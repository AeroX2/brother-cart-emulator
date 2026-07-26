# CardIO.dll reverse-engineering notes

Everything below was recovered from **PED-Basic 1.07 / CardIO.dll 3.2.1.1** by
decompiling both binaries with Ghidra. Addresses use each binary's preferred
image base: `0x10000000` for `CardIO.dll`, `0x00400000` for `pelite.exe`,
`0x10000000` for `PeCommon.dll`.

## Turning a PES into an image.bin without PED-Basic

**This works.** `cardio-py/cardgen.py` (and its JavaScript port in `docs/`) build
a complete card image from `.pes` files with no PED-Basic and no DLLs.

The reason it turned out to be tractable: **almost nothing is generated.** The
two things a card carries per design — the stitch stream and the preview
thumbnails — are copied *verbatim* out of the `.pes`. Everything else is either
a small computed table or a constant blob.

### The three parts of a card

| Part | Where it comes from |
|------|--------------------|
| Header, pointer tables, descriptor blocks | computed from pattern metadata (mapped above) |
| Glyph/font block, `0x1100`–`0x191E8` | **static** — the machine's built-in lettering, copied verbatim out of `CardIO.dll`'s `.data`. Does not depend on the designs. |
| Pattern data section | stitch streams and thumbnails, copied verbatim from the `.pes` |

The glyph block is the bulk of a card (98 KB of the ~123 KB a typical card uses)
and is hoop-dependent, so `cardgen.py` lifts it from a reference image rather
than reconstructing it.

### What each pattern needs (stage 1)

Everything comes straight out of the PEC block of the `.pes`:

```
pec        = u32 at PES+8
blocks     = pec[0x30]                  # colour changes; == CMExeEmb+0x54
stitches   = pec + 0x200 + 0x0D  ...  up to and including the 0xFF end opcode
thumbnails = pec + 0x200 + u24(pec+0x202), (blocks + 1) records of 0xE4 bytes
sew buffer = [0xF0, width LE16, height LE16] + stitch stream
```

The 5-byte prefix is the mask header `GetMaskData` expects (`0xF0` selects the
two-word form). Width and height are the stitch extent, and in a real card they
match the walked extent exactly.

### The 0xE4 records are the preview thumbnails

228 bytes = 6 bytes × 38 rows = a **48 × 38 monochrome bitmap**, drawn with a
rounded border frame. There is one for the whole design plus one per colour
block, which is exactly `blocks + 1` — matching the constraint `ChkPesFormat`
enforces (`CMExeEmb+0x54 == CMExeEmb+0x8C - 1`). PEC files store the same
bitmaps in the same layout, so they are copied across unchanged.

### Verification

`python cardgen.py --selftest` pulls the generator's own inputs back out of the
known-good card image, regenerates all 521,024 bytes, and requires an exact
match. It passes. The JavaScript port is checked against the Python and produces
byte-identical output.

Caveats worth keeping in mind:

- Verified against **one** reference card (hoop 0, 512 KiB, 3 patterns). Other
  hoop sizes need their own glyph block, which this does not have.
- A single-colour design has `blocks == 0`, so its attribute byte is written as
  `0xFF` (`blocks - 1`). That follows the decompiled code but has not been seen
  in a real PED-Basic card.
- No generated card has been run on a sewing machine.

### The alternative, if you want belt and braces

Running PED-Basic with the replacement `CardIO.dll` still works and is correct by
construction — pelite parses the PES with its own code and the shim's `Send()`
writes the image. Useful as a cross-check: generate the same design both ways
and diff.

### `CMExeEmb` layout (0xF0 bytes)

Recovered from the constructor (`0x10008450`) and the fields the CardIO
serializer reads. Offsets into the object:

| Offset | Field | Notes |
|--------|-------|-------|
| `0x10` | flag | ctor sets 1 |
| `0x14` | type | 0/1/2; selects which sew buffers exist |
| `0x48` / `0x4c` | sew length / pointer | the stitch stream; `GetMaskData` walks this |
| `0x50` | sew flag | |
| `0x54` / `0x58` | block count / pointer | per-block colour-needle bytes, remapped by pelite |
| `0x84` | `CPtrArray` | array of 228-byte (`0xE4`) block records — copied verbatim to the card |
| `0x8c` | (paired with `0x88`) | second `CPtrArray` backing store |
| `0xac` | `CDWordArray` | |
| `0xc0` | `CByteArray` | |
| `0xd4` | `CWordArray` | |
| `0xe8` | flag | `1` when the first sew byte was `0xFF` |

Before the write, pelite remaps the `+0x58` bytes through `FUN_004077c0` (a
palette lookup in pelite, not in either DLL) — so even a perfect PeCommon +
CardIO drive still needs that small pelite-side table to match byte-for-byte.

### The PES loader (`FUN_00426e0b` in pelite)

Reads `#PES`, then a 4-byte version tag, and branches. For `#PES0001` it reads
two 16-bit dimensions and a pattern count, allocates `count * 0xF0` bytes of
`CMExeEmb`, calls each object's virtual `Serialize`, then `ChkPesFormat`. Later
`#PESnnnn` tags read extra fields and call `SerializeAdditionalColorCodes`,
`SerializeThreadLCDData` and `SerializeRGBData`. All six of the user's sample
files are `#PES0001`, the simplest branch.

## The interface

`CardIO.dll` exports nine symbols, all `__thiscall` members of a single class.
`pelite.exe` imports seven of them (not `operator=`, not `WriteExecutableNum`),
and binds **by name**, so ordinals are not load-bearing.

| Ord | Signature |
|-----|-----------|
| 1 | `CCardIO::CCardIO(int cardType)` |
| 2 | `CCardIO::~CCardIO()` |
| 3 | `CCardIO &CCardIO::operator=(const CCardIO &)` |
| 4 | `CIOError CCardIO::ChkCardVolume(CObArray &, int &total, int &used, CCardAtrbType *)` |
| 5 | `CIOError CCardIO::ChkCardWriterConnected(int port, unsigned char *version, int *out)` |
| 6 | `CIOError CCardIO::Receive(CObArray *, int, const void *, const void *)` |
| 7 | `void CCardIO::ResetCardID()` |
| 8 | `CIOError CCardIO::Send(CObArray &, const void *progressFn, const void *progressCtx, CCardAtrbType *)` |
| 9 | `CIOError CCardIO::WriteExecutableNum(int)` |

`CCardIO` is **8 bytes** — `pelite.exe` allocates it with `operator new(8)` at
`0x00413404`. Layout: three card-ID bytes at offset 0 (`ResetCardID` is exactly
`memset(this, 0, 3)`), then the constructor's `int` at offset 4.

`Send`'s second and third arguments are a progress callback and its context.
`pelite.exe` passes `FUN_0040fc23` and its own `this`; `CardIO.dll` invokes it as
`void __cdecl cb(void *ctx, int percent)` eight times during a transfer.

## CIOError

**`0x18` is success.** Every other value is an error. `pelite.exe` tests
`== 0x18` and calls its error-reporting helper otherwise, at `0x0041342B`
(`Send`) and `0x00413437` (`ChkCardVolume`).

| Value | Meaning |
|-------|---------|
| `0x01` | card writer not connected / device would not open |
| `0x03` | no card present |
| `0x04` | wrong or unrecognised card |
| `0x05` | card busy |
| `0x06` | data too large for the card |
| `0x0B` | out of memory |
| `0x17` | bad card volume / requested hoop smaller than required |
| `0x18` | **success** |

`FUN_1000203d` maps low-level device error codes onto this enum (1→0x0E, 2→0x0F,
3→0x10, 4→0x11, …).

## Card geometry

`FUN_10005D94` (the body of `Send`) picks the card size from a size code the DLL
reads back from the hardware into its scratch object at offset `0x1C`:

| Size code | Bytes | |
|-----------|-------|-|
| 1 | `0x80000` | 512 KiB |
| 2 | `0x100000` | 1 MiB |
| 3 | `0x200000` | 2 MiB |

Anything else returns `0x17`. The ESP32 emulator in this repo uses a 512 KiB
flash chip (`FLASH_CHIP_CAPACITY` in `code-esp32/src/flashchip.h`), i.e. code 1.

## How a card actually gets written

`Send` → `FUN_10005D94`, which does, in order:

1. `FUN_1000A180` / `FUN_1000A1EC` — open the USB device. Failure returns `0x01`.
2. `FUN_100066C0` — identify the writer and card; must return `0x18`.
3. Choose the buffer size from the size code, allocate it, and **`memset` it to
   `0xFF`** (so untouched card space reads as erased flash).
4. `FUN_10006752` — walk the `CObArray` and work out the required hoop index.
5. If the caller supplied a `CCardAtrbType *`, reject with `0x17` when the
   requested hoop is smaller than required; otherwise adopt the caller's value.
6. `FUN_10006AC8` — **serialise every pattern into the buffer.** This is the
   whole card-image format, and it is a pure computation: four calls
   (`FUN_10006B11`, `FUN_10006E0B`, `FUN_100071EB`, `FUN_1000908A`) that touch
   only the buffer and the `CObArray`. No device I/O.
7. Transfer the buffer to the card in eight chunks via `FUN_1000AADA`, calling
   the progress callback after each.
8. Write three `rand()` bytes at offset `0x18E` — a per-card serial.
9. Write a single byte `0x62` (`'b'`) at a hoop-dependent offset.
10. Return `0x18`.

Step 6 is why `cardio.py` loads the stock DLL and calls `FUN_10006AC8` directly
instead of reimplementing the format: the serialiser *is* the DLL.

The constructor is not incidental either — it reads `pelite.exe`'s own version
resource (`LegalTrademarks`, `FileVersion`) and the current date into DLL
globals at `0x1003D340`, `0x1003D32C` and `0x1003D318`, and step 6 bakes those
into the card header. That is where `created by PED-Basic` at offset 50 comes
from.

### The "broth" byte

Step 9 writes the `'b'` that completes `brother` in the header. Because it lands
*after* the bulk transfer, any dump taken from the in-memory buffer before that
point shows `\xFFroth`. `image-dumper/cracker.py` repairs this by hand.

The offset depends on the hoop index:

| Hoop index | Offset |
|------------|--------|
| 0 | `0x100` |
| 1 | `0x170` |
| 2 | `0xC0` |
| 3 | `0x28E` |
| 4 | `0x280` |

> **Bug in `image-dumper/cracker.py`:** its `broth_locations_candidates` list is
> `[0xC0, 0x100, 0x170]`, so hoop indices 3 and 4 are never repaired and those
> images keep a corrupt header. The full table is above.

## What cracker.py was patching, and why none of it is needed here

| Address | Binary | Purpose |
|---------|--------|---------|
| `0x4136EA`–`0x4136EF` | pelite.exe | ignore a non-`0x18` result |
| `0x41C7C1`–`0x41C7C2` | pelite.exe | ignore a non-`0x18` result |
| `0x413DF1` | pelite.exe | ignore a non-`0x18` result |
| `0x10005DD8` | CardIO.dll | skip the writer firmware check |
| `0x10005E20` | CardIO.dll | skip the flash-ID / card-content check |
| `0x10005E6B` | CardIO.dll | force the card size |

Every one of these exists to stop the stock DLL reporting "no hardware". A
replacement DLL that simply *returns* `0x18` and the card size makes all six
patches unnecessary — including the three in `pelite.exe`, which is why this
approach needs no write access to the application binary and does not break when
Brother ships a different build.

## What the serialiser actually does

`FUN_10006AC8` is not an encoder. It is a **layout engine**: it writes a fixed
header, lays out a table of pointers, and `memcpy`s blocks that were already
encoded by `PeCommon.dll` into place. The two leaf functions make this explicit:

```c
FUN_10009F87(this, src, &cursor)          // memcpy(buf + cursor, src, 0xE4); cursor += 0xE4
FUN_10009FC0(this, src, len, &cursor)     // 4 zero bytes, then memcpy(buf + cursor, src, len)
```

`FUN_1000908A` feeds the second one from `CMExeEmb` fields `+0x4C` (data
pointer) and `+0x48` (length). **The stitch data is copied verbatim.** Nothing in
`CardIO.dll` understands stitches, colours or geometry — PED-Basic has already
produced the encoded blocks and this DLL only decides where they go.

### Does it generate the PES data?

Partly — the distinction matters if you want to reproduce it.

*Not generated:* the stitch payload. It arrives already encoded on the
`CMExeEmb` objects and is `memcpy`'d in, prefixed with four zero bytes. Likewise
the `0xE4`-byte records copied by `FUN_10009F87` come straight off the
sub-array at `CMExeEmb+0x84`.

*Generated:* everything that wraps it. The header, the pointer tables, the
column-major attribute table, and — in `FUN_100086FA` (2448 bytes) — a set of
group records built byte by byte, emitting a `0x0C` tag, a 3-byte pointer, the
constants `0x0003` and `0xC823`, and per-group counts, chunked
`0x17`/`0x19` patterns at a time. So the card's container structure is
synthesised here even though the stitches are not.

The practical consequence: a Python rewrite never has to encode an embroidery
stitch. It has to lay out a container and copy opaque blobs into it.

### Addressing

Card pointers are **3-byte little-endian**, written by
`FUN_1000A019(this, value, offset)`, and biased:

```
card_pointer = 0x400000 + offset_into_image
```

So the descriptor block at image offset `0x1069` is referenced as `0x401069`.

### Header

Everything below was read out of `FUN_10006B11` and then **verified byte-for-byte
against a real card image** (`code-esp32/data/image.bin`). Run
[`cardhdr.py`](cardhdr.py) on any dump to get this decoded automatically.

| Offset | Len | Contents | Example |
|--------|-----|----------|---------|
| `0x000` | ~85 | `"Copyright by brother industries ltd. Card data is created by %s system."` | |
| `0x0A0` | 1 | `00` | |
| `0x0A1` | 3 | pointer to a 9-byte block appended after the patterns | `0x404389` |
| `0x0B7` | 1 | `F1` | |
| `0x0D0` | 16 | `LegalTrademarks`, `strncpy`'d to 16 bytes — **not NUL-terminated when full** | `PED-Basic Ver 1.` |
| `0x0E0` | 16 | `FileVersion`, spaces stripped, `,` turned into `.` | `1.0.7.1` |
| `0x0F0` | ~20 | `"%04d/%02d/%02d date"` | `2022/07/16 date` |
| `0x100` | 14 | `brother_sewing` (hoop 0 — see below) | |
| `0x110` | 1 | `5E` (`'^'`) | |
| `0x116` | 2 | `FB FF` | |
| `0x120` | 3 | fixed `0x410000` | |
| `0x128` | 3 | fixed `0x410004` | |
| `0x130` | 3 | fixed `0x410008` | |
| `0x150` | 3 | zero | |
| `0x153` | 3 | zero | |
| `0x156` | 1 | `0A` | |
| `0x157` | 3 | pointer into the hoop block | `0x404358` |
| `0x164` | 1 | `00` | |
| `0x165` | 3 | pointer into the hoop block | `0x404364` |
| `0x168` | 1 | `1` when a "type 1" pattern is present | |
| `0x186` | 1 | `00` | |
| `0x187` | 3 | pointer into the hoop block | `0x40435E` |
| `0x18A` | 1 | `00` | |
| `0x18B` | 3 | pointer into the hoop block | `0x40435E` |
| `0x18E` | 3 | card serial: three `rand()` bytes, **written last over USB** | |

Everything not listed is left as `0xFF`.

Note the `0x0D0` gotcha: the trademark is copied with `strncpy(dst, src, 0x10)`,
so when it is exactly 16 characters there is no terminator and it runs straight
into the version field at `0x0E0`. A naive C-string read yields
`PED-Basic Ver 1.1.0.7.1`.

The `%s` substitution is why `created by PED-Basic` sits at offset 50 — that is
the exact index of the `c` in `created` within the format string, which is what
`cracker.py`'s sanity check keys off.

Two fields are **not** present in a `cracker.py` dump, because that dump is taken
from the staging buffer before the final USB writes: the `'b'` at `0x100`
(cracker.py patches it back in) and the card serial at `0x18E`, which stays
`FF FF FF`.

### Pointer table at `0x1000`

Verified against the same image (3 patterns, stride 2):

| Offset | Points at | Meaning |
|--------|-----------|---------|
| `0x1000` | `0x419221` | start of the pattern data section |
| `0x1003` | `0x401081` | per-pattern attribute table |
| `0x100F` + 3·i | `0x401069` + `stride`·i | eight slot descriptors |
| `0x1033`, `0x1036`, `0x1048`, `0x1057` | `0x401079`…`0x40107F` | four more slots |
| `0x1042`, `0x1045`, `0x1051`, `0x1054`, `0x105A` | `0x401084` + 3·k | attribute columns 1–5 |

Two useful identities fall out, both used by `cardhdr.py`:

```
stride        = ptr(0x1012) - ptr(0x100F)      # 1, or 2 when both pattern kinds present
pattern_count = ptr(0x1042) - ptr(0x1003)
```

The attribute table is **column-major**: for `n` patterns, column `c` of pattern
`i` lives at `base + c*n + i`. The six columns are
`kind`, `0x32`, `blocks-1`, `0x40`, `0x06`, `0x00`.

### Pattern tables (`FUN_10006E0B`)

A stride (`1` or `2`, `2` when both pattern kinds are present) interleaves the
tables. Eight pointers starting at `0x100F` (3 bytes each) point at
`0x401069 + i*stride`, then five more fixed entries, then a per-pattern
descriptor table at `0x1069` with twelve interleaved byte fields
(`08 00 A0 67 00 01 FF FF 00 00 <04|06> 00`).

### Hoop block (`FUN_100071EB`) — and the "broth" byte

The DLL holds the string `brother_sewing` at `0x1003D040`. It copies **13 bytes
starting at index 1** — `rother_sewing` — to `hoop_offset + 1`, deliberately
leaving `hoop_offset` itself as `0xFF`. The missing `b` is written **last**, over
USB, only after the whole card has transferred successfully.

That is the entire mystery behind `\xFFroth` in a memory dump: it is not
corruption, it is a commit marker. An interrupted write leaves a card whose magic
string is incomplete, so the sewing machine rejects it.

| Hoop index | String at | `'b'` at | Note |
|------------|-----------|----------|------|
| 0 | `0x101` | `0x100` | also calls `FUN_1000830D` |
| 1 | `0x171` | `0x170` | |
| 2 | `0xC1`  | `0xC0`  | |
| 3 | — | `0x28E` | no string copy in this branch |
| 4 | `0x281` | `0x280` | |

## Can it be rewritten fully in Python?

Yes. Nothing here is hostile — no obfuscation, no anti-debug, no checksums, and
critically **no stitch codec**. What remains is:

1. ~40 constant header field writes (mapped above).
2. Pointer-table arithmetic with 3-byte biased pointers (mapped above).
3. Section-offset maths in `FUN_1000908A` — records are `0xE4` bytes each.
4. Large static blobs sitting in the DLL's `.data` (200 KB of its 256 KB). The
   strings inside them (`project name DRAGON 3`, `MPU MITSUBISHI M37700`,
   `version 1.0 1991/05/15`, `8k…`) show these are card system-area templates for
   several card generations. They can be extracted as data files rather than
   regenerated.
5. Reading `CMExeEmb` fields — `+0x48` length, `+0x4C` data, `+0x54` count,
   `+0x84` sub-array, `+0xE8` flag. This must happen **in-process**, which the
   C++ shim already arranges.

The decisive advantage is that a rewrite is **differentially testable**: the shim
can build the same card image twice — once through the stock DLL, once through
the Python implementation — and `memcmp` them. That is an exact oracle, so the
port can proceed function by function with no guessing and no sewing machine
required.

## PES validation lives in PeCommon.dll, not CardIO.dll

Worth stating plainly because it is easy to assume otherwise: **`CardIO.dll`
never parses a `.pes` file.** By the time `Send()` is called the design is a
`CMExeEmb` object and the stitch stream is an opaque blob at `+0x4C` that gets
`memcpy`'d onto the card.

The gate is `CMExeEmb::ChkPesFormat(unsigned short machine, long *, CSize &)` in
`PeCommon.dll` at `0x10009BB0`. It walks the PEC stitch stream and returns `0`
the instant it meets something it does not recognise. [`pescheck.py`](pescheck.py)
is a port of that walk.

### Legal opcodes

| Byte | Meaning | Advances |
|------|---------|----------|
| high nibble `0x00`–`0x70` | short stitch delta, signed 7-bit (bit 6 is the sign) | 1 per axis |
| high nibble `0x80` | long stitch delta, signed 12-bit big-endian | 2 per axis |
| high nibble `0x90`, `0xA0` | move/jump, two signed 12-bit big-endian deltas | 4 |
| `0xB0` exactly | colour change, plus one operand byte | 2 |
| `0xC0`, `0xE0`, `0xE2` exactly | two-byte command | 2 |
| `0xFE` exactly | one-byte command (precedes `0xB0` in real files) | 1 |
| `0xFF` exactly | end of stitches | — |

Everything else — `0xB1`–`0xBF`, all of `0xD0`–`0xDF`, `0xE1`, `0xE3`–`0xEF`,
`0xF0`–`0xFD` — makes it `return 0`. Stitch coordinates are also bounds-checked
against the declared extent after every opcode; going negative or past the
extent is an immediate reject.

### The colour-change parity rule

This is the one that bites modern files. On each `0xB0` the validator does:

```c
local_8 = local_8 + 1;              // count this colour change
if ((local_8 % 2) != (operand & 1)) return 0;
```

So the operand of `FE B0 xx` must alternate **odd first**: `1, 2, 1, 2, …`.
Plenty of current converters emit `2, 1, 2, 1, …` instead — correctly
alternating, wrong phase — and PED-Basic 1.07 rejects the file outright.

The operand carries no colour information (the palette lives at `PEC+0x31`), so
re-phasing it is safe: `pescheck.py --fix` rewrites one byte per colour change
and leaves stitches, extents and colours untouched.

At `0xFF` the validator additionally requires the colour-change count to equal
`CMExeEmb+0x54`, and that in turn to equal `CMExeEmb+0x8C - 1`. Palette entries
outside `1..0x41` are clamped to `0x41` rather than rejected.

### Size and colour limits

From `ChkPesFormat`'s `machine` argument. Sizes in 0.1 mm.

| Machine | Max width | Max height | Max colours | Either orientation? |
|---------|-----------|------------|-------------|---------------------|
| D3 | 1000 | 1000 | < 64 | no |
| D4 | 1300 | 1800 | < 64 | no |
| D5 | 1600 | 2600 | < 100 | no |
| Sapphire | 3000 | 2000 | < 128 | yes |
| D6 | 1800 | 3000 | < 100 | yes |

D3 and D4 escalate rather than fail — a design too big for D3 is retried as D4
with a `CSize` of 130×180, and too big for D4 is retried as D5 at 160×260. Only
D5 and above fail outright. Sapphire and D6 retry with width and height swapped,
so they accept a design in either orientation.

## Still unknown

- The `CObArray` elements are `CMExeEmb` objects from `PeCommon.dll`, but
  `pelite.exe` dereferences an element once more than `CardIO.dll` does
  (`piVar3 = element; iVar2 = *piVar3;` at `0x004133F0` versus a direct
  `elem+0x54` access in `FUN_10006752`). The element is probably a small wrapper
  holding a `CMExeEmb *` at offset 0. `cardio.py`'s capture mode dumps the first
  0x100 bytes of each element so this can be settled from real data.
- `FUN_100086FA` (2448 bytes) and `FUN_100096D8` (1394 bytes) are the two largest
  unread functions; both look like template-blob emitters.
- The USB layer (`FUN_1000A180`…`FUN_1000AFED`) opens a handle stored at `+0x204`
  and drives named requests — `GetFirmVersionRequest`, `GetCardExistRequest`,
  `ReadCardDataRequest`, `WriteCardDataRequest`. Only needed to talk to real
  hardware; irrelevant to dumping images.
- `Receive` (reading a card back) has not been analysed.
