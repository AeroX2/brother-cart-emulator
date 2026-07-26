# cardio-py — a CardIO.dll replacement in Python

A drop-in replacement for PED-Basic's `CardIO.dll` that pretends to be a Brother
embroidery-card writer and saves the card image to a file.

This replaces the `image-dumper/cracker.py` approach. That script runs PED-Basic
under radare2 and patches six hardcoded byte offsets across two binaries to stop
the stock DLL noticing there is no card writer attached, then scrapes the image
out of process memory. It breaks whenever either binary changes, needs write
access to `pelite.exe`, and needs radare2 and r2pipe.

Here, PED-Basic loads a DLL that reports a healthy writer and a blank card, and
writes the image to `image.bin`. No debugger, no patching, nothing modified in
the PED-Basic install except renaming one file.

See [NOTES.md](NOTES.md) for the reverse-engineering the implementation rests on.

## How it fits together

```
pelite.exe  ──__thiscall──▶  CardIO.dll (this repo, 32-bit C++ shim)
                                   │
                                   ├── embedded CPython ──▶ cardio.py
                                   │                            │
                                   │        image serialising   │
                                   └── CardIO_orig.dll ◀────────┘
                                        (the stock DLL, used only
                                         as a pattern serialiser)
```

`src/CardIO.cpp` is pure ABI glue: it exports the same nine mangled `__thiscall`
symbols as the original (same names, same ordinals) and forwards every call to
`cardio.py`. All behaviour lives in the Python.

`cardio.py` does not reimplement the Brother card-image format. That format *is*
the bulk of the original DLL, so instead we load the stock DLL and call its two
pure serialiser functions directly with `ctypes`. Only two offsets are involved
(`0x6752` and `0x6AC8`), and they are never patched — just called.

## Building

Needs Visual Studio 2022 with the **x86** C++ toolset. `pelite.exe` is 32-bit,
so the DLL must be too.

```bash
cardio-py\build.bat
```

That produces `build\CardIO.dll`: x86, statically linked CRT, no dependency
beyond `KERNEL32.dll`, so it drops in without any redistributable.

## Installing

You need a **32-bit** Python — the interpreter is loaded into `pelite.exe`, which
is 32-bit. Download the "Windows embeddable package (32-bit)" from python.org and
unpack it into `cardio-py\python-embed\`. Alternatively point the
`CARDIO_PYTHON_DLL` environment variable at any 32-bit `python3*.dll`.

Then, in `C:\Program Files (x86)\Brother\PED-Basic\`:

1. Rename `CardIO.dll` to `CardIO_orig.dll` — keep it, it does the serialising.
2. Copy in `build\CardIO.dll`, `cardio.py`, and the `python-embed\` folder.

Run `pelite.exe` as usual: add a `.pes` file, move it to the card side, and hit
write. `image.bin` appears next to the DLL, ready for the ESP32 emulator.

## Building a card image straight from .pes files

`cardgen.py` builds a complete card image with no PED-Basic involved:

```bash
python cardio-py\cardgen.py design1.pes design2.pes -o image.bin
```

It is verified byte-for-byte — `python cardio-py\cardgen.py --selftest` takes a
real PED-Basic card apart, rebuilds all 521,024 bytes from those inputs, and
requires an exact match.

This works because a card generates almost nothing: the stitch stream and the
48×38 preview thumbnails are copied verbatim out of the `.pes`, the header and
pointer tables are small computed structures, and the bulk of the card is a
static glyph/font block (the machine's built-in lettering) lifted from a
reference image.

Caveats: verified against one reference card only (hoop 0, 512 KiB), and nothing
generated has been sewn yet. Treat your first card as a test. Same functionality
is available in the browser via the [web toolkit](../docs/).

## Checking a .pes before you write it

`pescheck.py` replays PED-Basic's own stitch validator
(`CMExeEmb::ChkPesFormat` from `PeCommon.dll`) so you can tell whether a design
will be accepted without touching the GUI:

```bash
python cardio-py\pescheck.py "C:\path\to\*.pes"
```

It reports the opcodes used, stitch count, physical extent, which machine
generations the design fits, and any reason PED-Basic would reject it.

The common failure on modern files is the colour-change parity rule: PED-Basic
requires the `FE B0 xx` operand sequence to start odd (`1, 2, 1, …`) and many
current converters emit `2, 1, 2, …`. Re-run with `--fix` to write a corrected
copy alongside the original — it changes one byte per colour change and leaves
stitches, extents and colours identical:

```bash
python cardio-py\pescheck.py design.pes --fix
```

## Inspecting a card image

`cardhdr.py` decodes and annotates the header of any card dump — no
dependencies, and it never writes to the file:

```bash
python cardio-py\cardhdr.py code-esp32\data\image.bin
```

It reports the hoop layout, every named header field, the decoded 3-byte
pointers, the pattern count and the attribute table. It also flags a dump whose
leading `'b'` at the `brother_sewing` marker is missing, which is the signature
of an image scraped from memory before the writer committed it.

## Configuration

Optional `cardio_config.json` next to the DLL:

```json
{
  "output": "image.bin",
  "card_size_code": 1,
  "original_dll": "CardIO_orig.dll",
  "capture": true
}
```

`card_size_code` is `1` for 512 KiB, `2` for 1 MiB, `3` for 2 MiB. 512 KiB
matches the flash chip on the ESP32 board (`FLASH_CHIP_CAPACITY`). The
`CARDIO_OUTPUT`, `CARDIO_CARD_SIZE_CODE` and `CARDIO_ORIGINAL_DLL` environment
variables override the corresponding fields.

## Troubleshooting

Everything is logged to `cardio-py.log` beside the DLL — both the C++ shim and
the Python side write there, and every Python traceback lands in it. If
PED-Basic reports a card error, that file says why.

If the log is missing entirely, the DLL was never loaded; if it stops after
`attached`, no 32-bit Python was found.

## Status

The shim is built and verified: its export table is byte-identical to the stock
DLL's, and the `__thiscall` thunking and MFC `CObArray` layout are unit-checked.

The end-to-end path — PED-Basic actually writing an `image.bin` — has **not** been
run yet; it needs an interactive PED-Basic session. The serialiser call sequence
in `_build_image` was derived from static analysis, so expect that to be where
any first-run problem is. Compare output against a known-good dump such as
`code-esp32/data/image.bin`, and check `capture.bin` if the pattern list looks
wrong.
