// UI glue for the Brother card toolkit. All analysis lives in format.js.
(function () {
  'use strict';

  const F = window.BrotherFormat;
  const $ = (id) => document.getElementById(id);

  let pesFiles = [];   // {name, bytes, result}

  const esc = (s) => String(s).replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  const hex = (n, w) => '0x' + n.toString(16).toUpperCase().padStart(w || 0, '0');

  function readFiles(fileList, done) {
    const files = Array.from(fileList);
    if (!files.length) return;
    let pending = files.length;
    const out = [];
    files.forEach((file, i) => {
      const fr = new FileReader();
      fr.onload = () => {
        out[i] = { name: file.name, bytes: new Uint8Array(fr.result) };
        if (--pending === 0) done(out.filter(Boolean));
      };
      fr.onerror = () => { if (--pending === 0) done(out.filter(Boolean)); };
      fr.readAsArrayBuffer(file);
    });
  }

  function download(name, bytes) {
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function wireDrop(dropId, inputId, handler) {
    const drop = $(dropId);
    const input = $(inputId);
    input.addEventListener('change', () => {
      readFiles(input.files, handler);
      input.value = '';
    });
    ['dragenter', 'dragover'].forEach((ev) =>
      drop.addEventListener(ev, (e) => {
        e.preventDefault();
        drop.classList.add('over');
      }));
    ['dragleave', 'drop'].forEach((ev) =>
      drop.addEventListener(ev, (e) => {
        e.preventDefault();
        drop.classList.remove('over');
      }));
    drop.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files.length) {
        readFiles(e.dataTransfer.files, handler);
      }
    });
  }

  // ------------------------------------------------------------------ PES --

  function verdict(r) {
    if (!r.opcodesLegal) return { cls: 'bad', text: 'REJECTED' };
    if (r.ok) return { cls: 'ok', text: 'READY' };
    if (!r.fits || !r.fits.length) return { cls: 'bad', text: 'TOO LARGE' };
    return { cls: 'warn', text: 'NEEDS REPAIR' };
  }

  function renderPes() {
    const host = $('pesResults');
    host.innerHTML = '';

    pesFiles.forEach((f, idx) => {
      const r = f.result;
      const v = verdict(r);
      const card = document.createElement('div');
      card.className = 'card';

      let body = '';
      if (!r.stitches) {
        body = '<p>Could not read this file as a card-compatible design.</p>';
      } else {
        const mm = (n) => (n / 10).toFixed(1);
        body = `<dl>
          <dt>Format</dt><dd>${esc(r.version)}</dd>
          <dt>Stitches</dt><dd>${r.stitches.toLocaleString()}</dd>
          <dt>Colours</dt><dd>${r.colours} (${r.colourChanges} change${r.colourChanges === 1 ? '' : 's'})</dd>
          <dt>Size</dt><dd>${mm(r.width)} &times; ${mm(r.height)} mm</dd>
          <dt>Opcodes</dt><dd>${r.opcodes.map(([k, n]) => `${esc(k)} &times;${n}`).join(', ')}</dd>
          <dt>Fits</dt><dd>${r.fits.length ? r.fits.join(', ') : 'nothing'}</dd>
        </dl>`;
      }

      if (r.problems.length) {
        body += '<ul class="problems">' +
          r.problems.map((p) => `<li>${esc(p)}</li>`).join('') + '</ul>';
      }

      const canFix = r.stitches && !r.parityOk && r.ccPositions && r.ccPositions.length;
      card.innerHTML = `
        <div class="head">
          <span class="name">${esc(f.name)}</span>
          <span class="pill ${v.cls}">${v.text}</span>
          ${canFix ? `<button data-fix="${idx}">Repair &amp; download</button>` : ''}
        </div>
        <div class="body">${body}</div>`;
      host.appendChild(card);
    });

    host.querySelectorAll('button[data-fix]').forEach((btn) => {
      btn.addEventListener('click', () => fixOne(Number(btn.dataset.fix)));
    });

    const fixable = pesFiles.filter((f) => f.result.stitches && !f.result.parityOk);
    $('pesActions').hidden = pesFiles.length === 0;
    $('fixAll').disabled = fixable.length === 0;
    $('fixAll').textContent = fixable.length
      ? `Repair all ${fixable.length} fixable file${fixable.length === 1 ? '' : 's'}`
      : 'Nothing needs repair';
  }

  function fixedName(name) {
    return name.replace(/\.pes$/i, '') + '.fixed.pes';
  }

  function fixOne(idx) {
    const f = pesFiles[idx];
    const out = F.repairParity(f.bytes, f.result.ccPositions);
    download(fixedName(f.name), out);
  }

  function onPes(files) {
    files.forEach((f) => {
      f.result = F.checkPes(f.name, f.bytes);
      pesFiles.push(f);
    });
    renderPes();
  }

  // ----------------------------------------------------------- card image --

  function renderCard(f) {
    const d = F.decodeCard(f.name, f.bytes);
    const host = $('binResults');

    const rows = d.fields.map((x) =>
      `<tr><td>${hex(x.off, 3)}</td><td>${esc(x.value)}</td><td>${esc(x.label)}</td></tr>`
    ).join('');

    let attrs = '';
    if (d.attributes) {
      attrs = '<table><tr><th>column</th>' +
        Array.from({ length: d.patternCount }, (_, i) => `<th>#${i}</th>`).join('') +
        '</tr>' +
        d.attributes.map((c) =>
          `<tr><td>${esc(c.label)}</td>` +
          c.values.map((v) => `<td>${v.toString(16).toUpperCase().padStart(2, '0')}</td>`).join('') +
          '</tr>').join('') +
        '</table>';
    }

    host.innerHTML = `
      <div class="card">
        <div class="head">
          <span class="name">${esc(f.name)}</span>
          <span class="pill ${d.hoop === null ? 'bad' : 'ok'}">${
            d.hoop === null ? 'UNRECOGNISED' : 'hoop ' + d.hoop}</span>
        </div>
        <div class="body">
          <dl>
            <dt>Size</dt><dd>${d.size.toLocaleString()} bytes</dd>
            <dt>In use</dt><dd>${d.used.toLocaleString()} bytes (rest is erased 0xFF)</dd>
            <dt>Patterns</dt><dd>${d.patternCount ?? 'unknown'}</dd>
            <dt>Stride</dt><dd>${d.stride ?? 'unknown'}</dd>
          </dl>
          ${d.notes.length ? '<ul class="problems">' +
            d.notes.map((n) => `<li>${esc(n)}</li>`).join('') + '</ul>' : ''}
          <h3 style="font-size:.9rem;margin:1.2rem 0 .4rem;color:var(--muted)">Header fields</h3>
          <div class="tablewrap"><table>${rows}</table></div>
          ${attrs ? '<h3 style="font-size:.9rem;margin:1.2rem 0 .4rem;color:var(--muted)">Pattern attributes</h3><div class="tablewrap">' + attrs + '</div>' : ''}
        </div>
      </div>`;
  }

  // ------------------------------------------------------------------ init --

  wireDrop('pesDrop', 'pesInput', onPes);
  wireDrop('binDrop', 'binInput', (files) => renderCard(files[0]));

  $('fixAll').addEventListener('click', () => {
    pesFiles.forEach((f, i) => {
      if (f.result.stitches && !f.result.parityOk) fixOne(i);
    });
  });

  $('clearPes').addEventListener('click', () => {
    pesFiles = [];
    renderPes();
    $('pesActions').hidden = true;
    $('buildStatus').innerHTML = '';
  });

  // ---------------------------------------------------------- build card --

  let templatePromise = null;

  function getTemplate() {
    if (!templatePromise) {
      templatePromise = fetch('card-template.bin')
        .then((r) => {
          if (!r.ok) throw new Error(`card-template.bin: HTTP ${r.status}`);
          return r.arrayBuffer();
        })
        .then((b) => new Uint8Array(b));
    }
    return templatePromise;
  }

  function note(cls, html) {
    $('buildStatus').innerHTML = `<div class="panel${cls ? ' ' + cls : ''}">${html}</div>`;
  }

  $('buildCard').addEventListener('click', () => {
    if (!pesFiles.length) return;

    const bad = pesFiles.filter((f) => !f.result.stitches);
    if (bad.length) {
      note('flag', `<strong>Cannot build.</strong> ${esc(bad[0].name)} is not a ` +
                   'usable design.');
      return;
    }
    const unfixed = pesFiles.filter((f) => !f.result.parityOk);
    if (unfixed.length) {
      note('flag', '<strong>Repair first.</strong> ' +
        `${unfixed.length} file${unfixed.length === 1 ? '' : 's'} still ` +
        'fail the colour-change parity rule, so PED-Basic and the machine would ' +
        'reject them. Use "Repair all fixable files", then re-add the repaired ' +
        'copies and build again.');
      return;
    }

    note('', 'Building&hellip;');
    getTemplate().then((tpl) => {
      const pats = pesFiles.map((f) => F.patternFromPes(f.bytes));
      const { image, used } = F.buildCard(pats, tpl);
      download('image.bin', image);

      const rows = pats.map((p, i) =>
        `<tr><td>${esc(pesFiles[i].name)}</td>` +
        `<td>${p.blockCount} block${p.blockCount === 1 ? '' : 's'}</td>` +
        `<td>${(p.width / 10).toFixed(1)} &times; ${(p.height / 10).toFixed(1)} mm</td>` +
        `<td>${p.sew.length.toLocaleString()} B</td></tr>`).join('');

      const pct = (100 * used / image.length).toFixed(1);
      note('', `<strong>image.bin built and downloaded.</strong>
        <p class="sub">${image.length.toLocaleString()} byte card,
        ${used.toLocaleString()} bytes used (${pct}%).</p>
        <div class="tablewrap"><table>
          <tr><th>design</th><th>colours</th><th>size</th><th>stitch data</th></tr>
          ${rows}
        </table></div>
        <p class="sub">Verified to reproduce a real PED-Basic card byte-for-byte,
        but only against one reference. Test the first card you write.</p>`);
    }).catch((err) => {
      note('flag', `<strong>Build failed.</strong> ${esc(err.message)}`);
    });
  });
})();
