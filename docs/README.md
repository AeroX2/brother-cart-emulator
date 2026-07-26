# Brother Embroidery Card Toolkit (web)

A static, client-side site for GitHub Pages. Nothing is uploaded — every byte is
processed in the browser.

## What it does

- **Check `.pes` files** — replays PED-Basic's own validator
  (`CMExeEmb::ChkPesFormat`) opcode by opcode. A pass means the real application
  will accept the file. Reports stitches, physical size, machine/hoop fit, and
  every reason PED-Basic would reject it.
- **Repair colour-change parity** — the common reason modern `.pes` files are
  rejected. Rewrites one byte per colour change; stitches, extents and colours
  are untouched.
- **Build `image.bin`** — drop in the designs you want on one card and get back
  a flashable card image, generated entirely in the browser.
- **Inspect an `image.bin`** — decodes the card header, hoop layout, 3-byte
  pointers and the pattern attribute table.

## About the generator

It is a port of [`../cardio-py/cardgen.py`](../cardio-py/cardgen.py), which is
verified byte-for-byte: it can take a real PED-Basic card apart, rebuild all
521,024 bytes from those inputs, and match exactly. The JavaScript is checked
against the Python and produces identical output.

Read the caveats before flashing:

- Verified against **one** reference card (hoop 0, 512 KiB). Other hoop sizes
  need their own glyph block, which is not included.
- No generated card has been run on a sewing machine yet.
- `card-template.bin` is the static glyph/font block every card carries — the
  machine's built-in lettering. It is constant data, not design-specific.

Details in [../cardio-py/NOTES.md](../cardio-py/NOTES.md).

## Enabling GitHub Pages

Settings → Pages → Source: "Deploy from a branch", branch `main`, folder
`/docs`. The `.nojekyll` file keeps Pages from touching the assets.

## Files

| File | Role |
|------|------|
| `index.html` | page and styling |
| `format.js` | format logic, ported from `cardio-py/pescheck.py`, `cardhdr.py` and `cardgen.py` |
| `app.js` | drag-drop UI glue |
| `card-template.bin` | static glyph/font block (first `0x191E8` bytes of a reference card) |

`format.js` is a direct port of the Python tools and is cross-checked against
them: the same sample files produce identical results, and the card builder
produces byte-identical images.
