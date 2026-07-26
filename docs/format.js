// Brother card / PES format logic, ported from cardio-py/pescheck.py and
// cardio-py/cardhdr.py. Everything here runs in the browser -- no uploads.
//
// The PES validator is a faithful port of CMExeEmb::ChkPesFormat from
// PeCommon.dll (PED-Basic 1.07). Keep the two implementations in step; see
// cardio-py/NOTES.md for where each rule comes from.

// Machine generations, as ChkPesFormat's first argument. Sizes are 0.1 mm.
// Sapphire and D6 retry their check with width and height swapped, so they
// accept a design in either orientation.
const MACHINES = [
  { name: 'D3',       maxW: 1000, maxH: 1000, maxColours: 0x40, rotatable: false },
  { name: 'D4',       maxW: 1300, maxH: 1800, maxColours: 0x40, rotatable: false },
  { name: 'D5',       maxW: 1600, maxH: 2600, maxColours: 100,  rotatable: false },
  { name: 'Sapphire', maxW: 3000, maxH: 2000, maxColours: 0x80, rotatable: true  },
  { name: 'D6',       maxW: 1800, maxH: 3000, maxColours: 100,  rotatable: true  },
];

const CARD_SIZES = { 1: 0x80000, 2: 0x100000, 3: 0x200000 };

function s12(word) {
  const v = word & 0xfff;
  return (v & 0x800) ? v - 0x1000 : v;
}

function s7(byte) {
  const v = byte & 0x7f;
  return (byte & 0x40) ? v - 0x80 : v;
}

function be16(d, i) {
  return (d[i] << 8) | d[i + 1];
}

function le32(d, i) {
  return (d[i] | (d[i + 1] << 8) | (d[i + 2] << 16) | (d[i + 3] << 24)) >>> 0;
}

function u24(d, i) {
  return d[i] | (d[i + 1] << 8) | (d[i + 2] << 16);
}

/**
 * Replay ChkPesFormat's opcode loop over the stitch stream starting at `start`.
 * Returns {ok:false, why} on anything the real validator would reject.
 */
function walk(data, start) {
  let i = start;
  let x = 0, y = 0;
  let minx = 0, maxx = 0, miny = 0, maxy = 0;
  let colourChanges = 0;
  let parityOk = true;
  let stitches = 0;
  const opcodes = new Map();
  const ccPositions = [];

  const note = (k) => opcodes.set(k, (opcodes.get(k) || 0) + 1);

  for (;;) {
    if (i >= data.length) {
      return { ok: false, why: `ran off the end of the file at 0x${i.toString(16)}` };
    }

    const b = data[i];
    const hi = b & 0xf0;

    if (hi >= 0x90) {
      if (hi === 0x90 || hi === 0xa0) {
        if (i + 4 > data.length) return { ok: false, why: 'truncated long move' };
        x += s12(be16(data, i));
        y += s12(be16(data, i + 2));
        i += 4;
        note(`jump 0x${hi.toString(16).toUpperCase()}`);
        stitches++;
      } else if (b === 0xb0) {
        const operand = data[i + 1];
        ccPositions.push(i + 1);
        i += 2;
        colourChanges++;
        // The operand's low bit must alternate with the colour-change count,
        // i.e. real files emit 1, 2, 1, 2, ... starting odd.
        if ((colourChanges & 1) !== (operand & 1)) parityOk = false;
        note('colour change 0xB0');
        continue;
      } else if (b === 0xc0 || b === 0xe0 || b === 0xe2) {
        i += 2;
        note(`cmd 0x${b.toString(16).toUpperCase()}`);
        continue;
      } else if (b === 0xfe) {
        i += 1;
        note('0xFE');
        continue;
      } else if (b === 0xff) {
        note('end 0xFF');
        return {
          ok: true, at: i, opcodes, colourChanges, parityOk, stitches, ccPositions,
          bbox: [minx, miny, maxx, maxy],
        };
      } else {
        return {
          ok: false,
          why: `illegal opcode 0x${b.toString(16).toUpperCase()} at 0x${i.toString(16)}`,
        };
      }
    } else {
      // Short/long stitch: one delta per axis, each independently encoded.
      for (let axis = 0; axis < 2; axis++) {
        if (i >= data.length) return { ok: false, why: 'truncated stitch' };
        const bb = data[i];
        let delta;
        if ((bb & 0xf0) < 0x71) {
          delta = s7(bb);
          i += 1;
        } else {
          delta = s12(be16(data, i));
          i += 2;
        }
        if (axis === 0) x += delta; else y += delta;
      }
      note('stitch');
      stitches++;
    }

    if (x < minx) minx = x;
    if (x > maxx) maxx = x;
    if (y < miny) miny = y;
    if (y > maxy) maxy = y;
  }
}

/**
 * The PEC body sits after a 512-byte header, but the exact stitch start varies.
 * Try each plausible offset and keep the one that parses cleanly.
 */
function findStitchStart(data, pecOff, expectedChanges) {
  let best = null;
  const limit = Math.min(pecOff + 0x230, data.length);
  for (let cand = pecOff + 0x200; cand < limit; cand++) {
    const r = walk(data, cand);
    if (!r.ok) continue;
    if (expectedChanges !== null && r.colourChanges !== expectedChanges) continue;
    if (!best || r.stitches > best.result.stitches) best = { start: cand, result: r };
  }
  return best;
}

function fitsMachine(w, h, m) {
  if (w <= m.maxW && h <= m.maxH) return true;
  return m.rotatable && h <= m.maxW && w <= m.maxH;
}

/** Analyse one .pes file. Returns a plain object describing it. */
function checkPes(name, bytes) {
  const out = { name, size: bytes.length, ok: false, problems: [] };

  if (bytes.length < 12 ||
      bytes[0] !== 0x23 || bytes[1] !== 0x50 || bytes[2] !== 0x45 || bytes[3] !== 0x53) {
    out.problems.push('Not a PES file (missing the "#PES" magic).');
    return out;
  }

  out.version = new TextDecoder('latin1').decode(bytes.subarray(0, 8));
  const pecOff = le32(bytes, 8);
  out.pecOffset = pecOff;
  if (!(pecOff > 0 && pecOff < bytes.length)) {
    out.problems.push(`PEC offset 0x${pecOff.toString(16)} points outside the file.`);
    return out;
  }

  const colours = bytes[pecOff + 0x30] + 1;
  out.colours = colours;
  out.palette = Array.from(bytes.subarray(pecOff + 0x31, pecOff + 0x31 + colours));

  let found = findStitchStart(bytes, pecOff, colours - 1);
  if (!found) found = findStitchStart(bytes, pecOff, null);
  if (!found) {
    out.problems.push(
      'No valid stitch stream found. PED-Basic would reject this file.');
    return out;
  }

  const r = found.result;
  out.stitchStart = found.start;
  out.stitches = r.stitches;
  out.colourChanges = r.colourChanges;
  out.parityOk = r.parityOk;
  out.ccPositions = r.ccPositions;
  out.width = r.bbox[2] - r.bbox[0];
  out.height = r.bbox[3] - r.bbox[1];
  out.opcodes = Array.from(r.opcodes.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  out.opcodesLegal = true;

  out.fits = MACHINES.filter(
    (m) => fitsMachine(out.width, out.height, m) && colours < m.maxColours
  ).map((m) => m.name);

  const badPalette = out.palette.filter((c) => c === 0 || c > 0x41);
  if (badPalette.length) {
    out.problems.push(
      `Palette entries ${badPalette.join(', ')} fall outside 1..65 and will be clamped to 65.`);
  }
  if (!r.parityOk) {
    out.problems.push(
      'Colour-change operands start even (2, 1, 2, ...). PED-Basic requires ' +
      'them to start odd (1, 2, 1, ...) and rejects the file otherwise. ' +
      'This is repairable.');
  }
  if (!out.fits.length) {
    out.problems.push(
      'Too large for every hoop, in either orientation. The design itself ' +
      'needs resizing.');
  }

  out.ok = r.parityOk && out.fits.length > 0;
  return out;
}

/**
 * Re-phase the colour-change alternation to start odd. The operand is only an
 * alternation marker -- the thread colour comes from the palette table -- so
 * this changes no stitches and no colours.
 */
function repairParity(bytes, ccPositions) {
  const out = new Uint8Array(bytes);
  ccPositions.forEach((pos, k) => { out[pos] = (k % 2 === 0) ? 1 : 2; });
  return out;
}

// --------------------------------------------------------------- card image --

const HOOP_MARKERS = { 0: 0x100, 1: 0x170, 2: 0xc0, 3: 0x28e, 4: 0x280 };
const PTR_BIAS = 0x400000;

const CARD_FIELDS = [
  [0x000, 'str', 0x60, 'copyright line'],
  [0x0a1, 'ptr', 0,    'pointer to appended block'],
  [0x0d0, 'str', 0x10, 'trademark (from pelite.exe version resource)'],
  [0x0e0, 'str', 0x10, 'file version'],
  [0x0f0, 'str', 0x20, 'build date'],
  [0x110, 'u8',  0,    'always 5E'],
  [0x120, 'ptr', 0,    'fixed 0x410000'],
  [0x128, 'ptr', 0,    'fixed 0x410004'],
  [0x130, 'ptr', 0,    'fixed 0x410008'],
  [0x156, 'u8',  0,    'always 0A'],
  [0x157, 'ptr', 0,    'pointer into hoop block'],
  [0x165, 'ptr', 0,    'pointer into hoop block'],
  [0x168, 'u8',  0,    '1 when a type-1 pattern is present'],
  [0x187, 'ptr', 0,    'pointer into hoop block'],
  [0x18b, 'ptr', 0,    'pointer into hoop block'],
  [0x18e, 'u24', 0,    'card serial (three random bytes)'],
];

function cstr(d, off, limit) {
  const out = [];
  for (let i = off; i < off + limit && i < d.length; i++) {
    if (d[i] === 0x00 || d[i] === 0xff) break;
    out.push(d[i]);
  }
  return new TextDecoder('latin1').decode(Uint8Array.from(out));
}

/** Decode the header of a card image (image.bin). */
function decodeCard(name, d) {
  const out = { name, size: d.length, fields: [], pointers: [], notes: [] };

  let used = d.length;
  while (used > 0 && d[used - 1] === 0xff) used--;
  out.used = used;

  out.hoop = null;
  for (const [idx, off] of Object.entries(HOOP_MARKERS)) {
    const full = cstr(d, off, 14) === 'brother_sewing';
    const partial = cstr(d, off + 1, 13) === 'rother_sewing';
    if (full || partial) {
      out.hoop = Number(idx);
      out.hoopOffset = off;
      out.committed = full;
      break;
    }
  }
  if (out.hoop === null) {
    out.notes.push('No "brother_sewing" marker found - this may not be a card image.');
  } else if (!out.committed) {
    out.notes.push(
      'The leading "b" of the marker is missing. This image was scraped from ' +
      'memory before the writer sent its final commit byte.');
  }

  for (const [off, kind, len, label] of CARD_FIELDS) {
    let value;
    if (kind === 'str') value = JSON.stringify(cstr(d, off, len));
    else if (kind === 'u8') value = d[off].toString(16).toUpperCase().padStart(2, '0');
    else if (kind === 'u24') value = u24(d, off).toString(16).toUpperCase().padStart(6, '0');
    else {
      const raw = u24(d, off);
      value = raw === 0xffffff
        ? 'unset'
        : `0x${raw.toString(16).toUpperCase()} -> offset 0x${(raw - PTR_BIAS).toString(16).toUpperCase()}`;
    }
    out.fields.push({ off, value, label });
  }

  // Two identities fall out of the pointer table.
  const first = u24(d, 0x100f), second = u24(d, 0x1012);
  const stride = (second - first > 0 && second - first < 16) ? second - first : null;
  const count = u24(d, 0x1042) - u24(d, 0x1003);
  out.stride = stride;
  out.patternCount = (count > 0 && count < 256) ? count : null;

  if (out.patternCount) {
    const base = u24(d, 0x1003) - PTR_BIAS;
    const cols = ['kind', '0x32', 'blocks-1', '0x40', '0x06', '0x00'];
    out.attributes = cols.map((label, c) => ({
      label,
      values: Array.from({ length: out.patternCount },
                         (_, i) => d[base + c * out.patternCount + i]),
    }));
  }
  return out;
}

// ---------------------------------------------------------- card builder --
//
// Port of cardio-py/cardgen.py, which is verified byte-for-byte against a real
// PED-Basic card image. Layout comes from FUN_10006B11 / FUN_10006E0B /
// FUN_1000908A; see cardio-py/NOTES.md.

const REC = 0xE4;               // thumbnail / block record size
const MASK_TAG = 0xF0;          // 5-byte mask header: tag, width LE16, height LE16
const TEMPLATE_LO = 0x1100;
const TEMPLATE_HI = 0x191E8;    // == C0, where the pattern data section starts

function put3(buf, off, val) {
  buf[off] = val & 0xff;
  buf[off + 1] = (val >> 8) & 0xff;
  buf[off + 2] = (val >> 16) & 0xff;
}

/** GetMaskData: returns {start, width, height}. */
function maskHeader(buf) {
  const b = buf[0];
  if (b === 0xf0) {
    return { start: 5, width: buf[1] | (buf[2] << 8), height: buf[3] | (buf[4] << 8) };
  }
  if (b === 0xf1) {
    let w = 0, h = 0, i = 1;
    for (let k = 0; k < 4; k++) {
      w += buf[i] | (buf[i + 1] << 8);
      h += buf[i + 2] | (buf[i + 3] << 8);
      i += 4;
    }
    return { start: i, width: w, height: h };
  }
  if (b < 0x80) return { start: 2, width: b, height: buf[1] };
  return {
    start: 6,
    width: (b & 0x7f) + buf[2] + buf[4],
    height: (buf[1] & 0x7f) + buf[3] + buf[5],
  };
}

/**
 * stage 1: .pes -> the fields the card serializer consumes. The card stores the
 * PEC stitch stream verbatim behind a 5-byte mask header, and the PEC 48x38
 * thumbnails verbatim as the 0xE4 records.
 */
function patternFromPes(bytes) {
  if (!(bytes[0] === 0x23 && bytes[1] === 0x50 && bytes[2] === 0x45 && bytes[3] === 0x53)) {
    throw new Error('not a PES file');
  }
  const pec = le32(bytes, 8);
  if (!(pec > 0 && pec < bytes.length)) throw new Error('PEC offset out of range');

  const changes = bytes[pec + 0x30];
  const body = pec + 0x200;

  const found = findStitchStart(bytes, pec, changes);
  if (!found) throw new Error('no valid stitch stream; PED-Basic would reject this');
  if (!found.result.parityOk) {
    throw new Error('colour-change parity is wrong — repair it first');
  }

  const stream = bytes.subarray(found.start, found.result.at + 1);  // include 0xFF
  const w = found.result.bbox[2] - found.result.bbox[0];
  const h = found.result.bbox[3] - found.result.bbox[1];

  const sew = new Uint8Array(5 + stream.length);
  sew[0] = MASK_TAG;
  sew[1] = w & 0xff; sew[2] = (w >> 8) & 0xff;
  sew[3] = h & 0xff; sew[4] = (h >> 8) & 0xff;
  sew.set(stream, 5);

  const graphics = body + u24(bytes, body + 2);
  const thumbs = [];
  for (let i = 0; i <= changes; i++) {
    const t = bytes.subarray(graphics + i * REC, graphics + (i + 1) * REC);
    if (t.length !== REC) throw new Error('thumbnail block runs past end of file');
    thumbs.push(t);
  }

  return { sew, thumbs, blockCount: changes, width: w, height: h };
}

/** stage 2: lay patterns out into a complete card image. */
function buildCard(patterns, template, cardBytes) {
  cardBytes = cardBytes || 0x80000;
  const n = patterns.length;
  const buf = new Uint8Array(cardBytes).fill(0xff);

  // Static glyph/font block plus the header text, from the reference template.
  buf.set(template.subarray(TEMPLATE_LO, TEMPLATE_HI), TEMPLATE_LO);
  buf.set(template.subarray(0x00, 0x55), 0x00);
  buf.set(template.subarray(0xd0, 0xf0), 0xd0);
  buf.set(template.subarray(0xf0, 0xff), 0xf0);
  buf.set(template.subarray(0x157, 0x191), 0x157);
  put3(buf, 0xa1, u24(template, 0xa1));

  buf[0xa0] = 0;
  buf[0xb7] = 0xf1;
  buf[0x110] = 0x5e;
  buf[0x116] = 0xfb; buf[0x117] = 0xff;
  put3(buf, 0x120, 0x410000);
  put3(buf, 0x128, 0x410004);
  put3(buf, 0x130, 0x410008);
  put3(buf, 0x150, 0); put3(buf, 0x153, 0);
  buf[0x156] = 10;

  // hoop-0 marker; 0x100 is the final commit byte
  buf[0x100] = 0x62;
  buf.set([0x72, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x5f, 0x73, 0x65, 0x77, 0x69, 0x6e, 0x67], 0x101);

  const kinds = patterns.map((p) => (p.blockCount === 1 ? 0 : 1));
  const hasT1 = kinds.some((k) => k === 1);
  const hasT0 = kinds.some((k) => k === 0);
  const stride = (hasT1 && hasT0) ? 2 : 1;

  const desc = 0x1069;
  let off = 0x100f;
  for (let i = 0; i < 8; i++) { put3(buf, off, 0x400000 + desc + i * stride); off += 3; }
  const p = desc + 8 * stride;
  put3(buf, 0x1033, 0x400000 + p);
  put3(buf, 0x1036, 0x400000 + p + stride);
  let iv = desc + 10 * stride;
  put3(buf, 0x1048, 0x400000 + iv); iv += stride;
  put3(buf, 0x1057, 0x400000 + iv); iv += stride;
  put3(buf, 0x1003, 0x400000 + iv);
  [0x1042, 0x1045, 0x1051, 0x1054, 0x105a].forEach((addr, k) => {
    put3(buf, addr, 0x400000 + iv + n * (k + 1));
  });

  const fixed = [8, 0, 0xa0, 0x67, 0, 1, 0xff, 0xff, 0, 0];
  for (let lane = 0; lane < stride; lane++) {
    const c = desc + lane;
    fixed.forEach((v, col) => { buf[c + col * stride] = v; });
    buf[c + 10 * stride] = (lane === 0 && hasT1) ? 4 : 6;
    buf[c + 11 * stride] = 0;
  }

  const c0 = desc + stride * 12;
  patterns.forEach((pat, i) => {
    const c = c0 + i;
    buf[c + n * 0] = (stride === 2 && pat.blockCount !== 1) ? 1 : 0;
    buf[c + n * 1] = 0x32;
    buf[c + n * 2] = (pat.blockCount - 1) & 0xff;
    buf[c + n * 3] = 0x40;
    buf[c + n * 4] = 6;
    buf[c + n * 5] = 0;
  });

  // FUN_1000908A data section
  const total = patterns.reduce((s, q) => s + q.blockCount, 0);
  const multi = patterns.reduce((s, q) => s + (q.blockCount !== 1 ? q.blockCount : 0), 0);
  const ones = patterns.map((q, i) => (q.blockCount === 1 ? i + 1 : 0)).filter(Boolean);
  const t68 = ones.length ? Math.max(...ones) : 0;

  const C0 = TEMPLATE_HI;
  let cur24 = C0;
  let l38 = C0 + n * 3;
  let l3c = l38 + (ones.length ? t68 * 3 : 0);
  let lc = l38 + (multi + t68) * 3;
  let l1c = lc + n * 3;
  let l14 = l1c + n * REC;
  let l10 = l14 + total * REC;

  put3(buf, 0x42a2, 0x400000 + l38);
  put3(buf, 0x1000, 0x400000 + lc);

  for (const pat of patterns) {
    put3(buf, cur24, 0x400000 + l1c); cur24 += 3;
    buf.set(pat.thumbs[0], l1c); l1c += REC;

    for (let j = 0; j < pat.blockCount; j++) {
      if (pat.blockCount === 1) {
        put3(buf, l38, 0x400000 + l14);
      } else {
        put3(buf, l3c, 0x400000 + l14 + j * REC);
        l3c += 3;
      }
    }
    l38 += 3;

    for (let k = 1; k <= pat.blockCount; k++) { buf.set(pat.thumbs[k], l14); l14 += REC; }

    put3(buf, lc, 0x400000 + l10); lc += 3;
    buf[l10] = 0; buf[l10 + 1] = 0; buf[l10 + 2] = 0; buf[l10 + 3] = 0;
    l10 += 4;
    buf.set(pat.sew, l10);
    l10 += pat.sew.length;
  }

  if (l10 > cardBytes) {
    throw new Error(`designs need ${l10} bytes but the card holds ${cardBytes}`);
  }
  return { image: buf, used: l10 };
}

// Plain global rather than an ES module, so the page also works when opened
// straight off disk (file:// blocks module loading).
window.BrotherFormat = {
  MACHINES, CARD_SIZES, walk, fitsMachine, checkPes, repairParity, decodeCard,
  patternFromPes, buildCard, maskHeader, TEMPLATE_HI,
};
