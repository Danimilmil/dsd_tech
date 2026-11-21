const $ = s => document.querySelector(s);
const EMP = { nome: 'DSD TECH INSTALAÇÕES', cnpj: '59.470.117/0001-81', tag: 'Qualidade e confiança na DSD TECH INSTALAÇÕES' };
const brl = n => new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(+n || 0).replace(/\u00a0/g, ' ');
const fdate = s => (s ? s.split('-').reverse().join('/') : '');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const digits = s => String(s || '').replace(/\D/g, '');
const lowerFirst = s => s.charAt(0).toLowerCase() + s.slice(1);
const today = () => new Date().toISOString().slice(0, 10);

function parseValor(s) {
  s = String(s).trim().replace(/[^\d.,]/g, '');
  if (s.includes(',')) s = s.replace(/\./g, '').replace(',', '.');
  return parseFloat(s);
}
function maskDoc(v) {
  const d = digits(v).slice(0, 14);
  if (d.length <= 11) return d.replace(/(\d{3})(\d)/, '$1.$2').replace(/(\d{3})(\d)/, '$1.$2').replace(/(\d{3})(\d{1,2})$/, '$1-$2');
  return d.replace(/^(\d{2})(\d)/, '$1.$2').replace(/^(\d{2})\.(\d{3})(\d)/, '$1.$2.$3').replace(/\.(\d{3})(\d)/, '.$1/$2').replace(/(\d{4})(\d)/, '$1-$2');
}
function validCPF(c) {
  if (c.length !== 11 || /^(\d)\1+$/.test(c)) return false;
  for (let t = 9; t < 11; t++) { let s = 0; for (let i = 0; i < t; i++) s += +c[i] * (t + 1 - i); if (((s * 10) % 11) % 10 !== +c[t]) return false; }
  return true;
}
function validCNPJ(c) {
  if (c.length !== 14 || /^(\d)\1+$/.test(c)) return false;
  for (let t = 12; t < 14; t++) { let s = 0, p = t - 7; for (let i = 0; i < t; i++) { s += +c[i] * p--; if (p < 2) p = 9; } const d = s % 11 < 2 ? 0 : 11 - (s % 11); if (d !== +c[t]) return false; }
  return true;
}

/* ---------- Armazenamento no navegador (localStorage) ---------- */
/* ---------- Cofre criptografado (AES-GCM + PBKDF2) ---------- */
const VKEY = 'dsd_vault', enc = new TextEncoder(), dec = new TextDecoder();
let vkey = null, vsalt = null, vault = { rec: [] };
const b64 = u => { let s = ''; new Uint8Array(u).forEach(b => (s += String.fromCharCode(b))); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function deriveKey(pw, salt) {
  const m = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' }, m, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function persist() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vkey, enc.encode(JSON.stringify(vault)));
  localStorage.setItem(VKEY, JSON.stringify({ s: b64(vsalt), i: b64(iv), d: b64(ct) }));
}
async function unlock(pw) {
  const raw = localStorage.getItem(VKEY);
  if (raw) {
    const o = JSON.parse(raw); vsalt = unb64(o.s);
    const k = await deriveKey(pw, vsalt);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.i) }, k, unb64(o.d));
    vkey = k; vault = JSON.parse(dec.decode(pt));
  } else {
    vsalt = crypto.getRandomValues(new Uint8Array(16)); vkey = await deriveKey(pw, vsalt);
    let old = []; try { old = JSON.parse(localStorage.getItem('dsd_recibos')) || []; } catch {}
    vault = { rec: old };
    await persist(); localStorage.removeItem('dsd_recibos'); localStorage.removeItem('dsd_sig');
  }
}
const loadAll = () => vault.rec;
const saveAll = () => persist();
const fail = (m, f) => { throw Object.assign(new Error(m), { field: f }); };
function norm(b) {
  return { valor_servico: Number(b.valor_servico), desconto_tipo: b.desconto_tipo, desconto_val: Number(b.desconto_val), desconto: Number(b.desconto), valor: Number(b.valor), data_pagamento: b.data_pagamento, status: b.status, pedido: String(b.pedido).trim(),
    descricao: String(b.descricao).trim(), cliente_nome: String(b.cliente_nome).trim(), cliente_doc: maskDoc(digits(b.cliente_doc)) };
}
async function api(url, opts = {}) {
  const m = opts.method || 'GET', list = loadAll(), u = new URL(url, location.origin), p = u.pathname;
  if (p === '/api/stats') return { total: list.length, recebido: list.filter(r => r.status === 'Pago').reduce((s, r) => s + r.valor, 0) };
  if (p === '/api/next-order') {
    const yy = String(new Date().getFullYear()).slice(-2);
    const n = Math.max(0, ...list.filter(r => r.pedido.endsWith('-' + yy)).map(r => parseInt(r.pedido) || 0));
    return { pedido: String(n + 1).padStart(4, '0') + '-' + yy };
  }
  if (p === '/api/receipts' && m === 'GET') {
    const q = (u.searchParams.get('q') || '').toLowerCase(), dq = digits(q);
    return list.filter(r => !q || r.cliente_nome.toLowerCase().includes(q) || r.pedido.toLowerCase().includes(q) || (dq && digits(r.cliente_doc).includes(dq))).sort((a, b) => b.id - a.id);
  }
  const id = +p.split('/')[3];
  if (m === 'DELETE') {
    const i = list.findIndex(r => r.id === id);
    if (i < 0) fail('Recibo não encontrado.');
    list.splice(i, 1); await saveAll(); return { ok: true };
  }
  const d = norm(opts.body);
  if (list.some(r => r.pedido.toLowerCase() === d.pedido.toLowerCase() && r.id !== id)) fail('Já existe um recibo com este número de pedido.', 'pedido');
  if (m === 'POST') { const r = { id: Math.max(0, ...list.map(x => x.id)) + 1, ...d }; list.push(r); await saveAll(); return r; }
  const i = list.findIndex(r => r.id === id);
  if (i < 0) fail('Recibo não encontrado.');
  list[i] = { id, ...d }; await saveAll(); return list[i];
}
let tt;
function toast(msg, bad) { const t = $('#toast'); t.textContent = msg; t.className = 'show' + (bad ? ' bad' : ''); clearTimeout(tt); tt = setTimeout(() => (t.className = ''), 3200); }

/* ---------- Navegação ---------- */
function show(v) {
  $('#v-dash').hidden = v !== 'dash'; $('#v-editor').hidden = v !== 'editor';
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b.dataset.view === v));
  if (v === 'dash') loadDash(); else fit();
  window.scrollTo(0, 0);
}
document.querySelectorAll('nav button').forEach(b => (b.onclick = () => (b.dataset.view === 'editor' ? newReceipt() : show('dash'))));
$('#goNew').onclick = () => newReceipt();

/* ---------- Dashboard ---------- */
let rows = [];
async function loadDash() {
  try {
    const [st, list] = await Promise.all([api('/api/stats'), api('/api/receipts?q=' + encodeURIComponent($('#search').value))]);
    $('#stTotal').textContent = st.total; $('#stSum').textContent = brl(st.recebido);
    rows = list;
    $('#rows').innerHTML = rows.map(r => `<tr><td>${esc(r.pedido)}</td><td>${esc(r.cliente_nome)}</td><td>${fdate(r.data_pagamento)}</td><td>${brl(r.valor)}</td>
      <td><span class="tag ${esc(r.status)}">${esc(r.status)}</span></td>
      <td><div class="acts"><button class="btn small" data-a="view" data-id="${r.id}">Visualizar</button><button class="btn small" data-a="pdf" data-id="${r.id}">Baixar PDF</button><button class="btn small ghost" data-a="edit" data-id="${r.id}">Editar</button><button class="btn small danger" data-a="del" data-id="${r.id}">Excluir</button></div></td></tr>`).join('');
    $('#empty').hidden = rows.length > 0;
    $('#recent').innerHTML = rows.slice(0, 4).map(r => `<div data-a="view" data-id="${r.id}"><b>${esc(r.cliente_nome)}</b><span>Pedido ${esc(r.pedido)} · ${fdate(r.data_pagamento)}</span><span>${brl(r.valor)}</span></div>`).join('') || '<span class="muted">Nenhum recibo emitido ainda.</span>';
  } catch (e) { toast(e.message, true); }
}
let st;
$('#search').oninput = () => { clearTimeout(st); st = setTimeout(loadDash, 250); };
document.addEventListener('click', async e => {
  const el = e.target.closest('[data-a]'); if (!el) return;
  const r = rows.find(x => x.id == el.dataset.id); if (!r) return;
  if (el.dataset.a === 'pdf') return (await makePdf(r)).download(fileName(r));
  if (el.dataset.a === 'del') {
    if (!confirm(`Excluir o recibo ${r.pedido} de ${r.cliente_nome}?\n\nEsta ação não pode ser desfeita.`)) return;
    try { await api('/api/receipts/' + r.id, { method: 'DELETE' }); toast('Recibo excluído.'); loadDash(); }
    catch (err) { toast(err.message, true); }
    return;
  }
  loadIntoForm(r);
  if (el.dataset.a === 'view') { const p = await makePdf(r); openModal(p); }
});

/* ---------- Formulário ---------- */
const F = { valor: $('#valor'), data: $('#data'), status: $('#status'), pedido: $('#pedido'), descricao: $('#descricao'), desc: $('#desc'), nome: $('#nome'), doc: $('#doc') };
let cur = { id: null }, descAuto = true;
const sig = '/assets/assinatura.png'; /* assinatura fixa para todos os recibos */


const defDesc = p => `Recebimento referente ao pedido #${p}`;
const full = r => ({ ...r, valor_servico: r.valor_servico ?? r.valor, desconto: r.desconto || 0 });
const r2 = n => Math.round(n * 100) / 100;
const pctOf = d => (d.valor_servico > 0 ? r2(d.desconto / d.valor_servico * 100) : 0);
const fmtPct = n => String(n).replace('.', ',') + '%';
function calcDesc(serv, val) {
  const dsc = Math.round(serv * val) / 100;
  return { desconto: dsc, valor: Math.round((serv - dsc) * 100) / 100 };
}
function readForm() {
  const vs = parseValor(F.valor.value) || 0, dv = parseValor(F.desc.value) || 0, c = calcDesc(vs, dv);
  return { valor_servico: vs, desconto_tipo: '%', desconto_val: dv, desconto: c.desconto, valor: c.valor, data_pagamento: F.data.value, status: F.status.value,
    pedido: F.pedido.value.trim(), descricao: F.descricao.value.trim(), cliente_nome: F.nome.value.trim(), cliente_doc: F.doc.value };
}
function validate(d) {
  const e = {};
  if (!(d.valor_servico > 0)) e.valor = 'Informe o valor do serviço.';
  else if (!(d.desconto_val >= 0 && d.desconto_val < 100) || !(d.valor > 0)) e.desc = 'Desconto inválido: informe um percentual de 0 a 99,99.';
  if (!d.data_pagamento) e.data = 'Informe a data.';
  if (!/^[A-Za-z0-9-]{1,20}$/.test(d.pedido)) e.pedido = 'Pedido obrigatório (letras, números e hífen).';
  if (!d.descricao) e.descricao = 'Informe a descrição.';
  if (d.cliente_nome.length < 3) e.nome = 'Informe o nome completo ou razão social.';
  const dg = digits(d.cliente_doc);
  if (!dg) e.doc = 'Informe o CPF ou CNPJ.'; else if (!(validCPF(dg) || validCNPJ(dg))) e.doc = 'CPF ou CNPJ inválido.';
  return e;
}
function showErrors(e) {
  document.querySelectorAll('.err').forEach(s => (s.textContent = e[s.dataset.for] || ''));
  const k = Object.keys(e)[0]; if (k && F[k]) F[k].focus();
  return !!k;
}
function pctVal(d, vs) {
  if (d.desconto_tipo === '%') return d.desconto_val || 0;
  return d.desconto > 0 && vs > 0 ? Math.round(d.desconto / vs * 1e6) / 1e4 : 0;
}
function setForm(d) {
  const vs = d.valor_servico ?? d.valor; F.valor.value = vs ? String(vs).replace('.', ',') : ''; F.desc.value = pctVal(d, vs) ? String(pctVal(d, vs)).replace('.', ',') : ''; F.data.value = d.data_pagamento || today(); F.status.value = d.status || 'Pago';
  F.pedido.value = d.pedido || ''; F.descricao.value = d.descricao || ''; F.nome.value = d.cliente_nome || ''; F.doc.value = d.cliente_doc || '';
  showErrors({}); render();
}
function loadIntoForm(r) { cur = { id: r.id }; descAuto = false; setForm(r); $('#edTitle').textContent = 'Editar recibo ' + r.pedido; show('editor'); }
async function newReceipt() {
  cur = { id: null }; descAuto = true; $('#edTitle').textContent = 'Novo recibo';
  let p = ''; try { p = (await api('/api/next-order')).pedido; } catch (e) { toast(e.message, true); }
  setForm({ pedido: p, descricao: defDesc(p) }); show('editor');
}
F.pedido.oninput = () => { if (descAuto) F.descricao.value = defDesc(F.pedido.value.trim()); render(); };
F.descricao.oninput = () => { descAuto = false; render(); };
F.doc.oninput = () => { F.doc.value = maskDoc(F.doc.value); render(); };
['valor', 'desc', 'data', 'status', 'nome'].forEach(k => (F[k].oninput = render));


/* ---------- Pré-visualização A4 ---------- */
function render() {
  const d = readForm();
  $('#calc').innerHTML = `<span>Desconto</span><b>${d.desconto > 0 ? '- ' + brl(d.desconto) : '—'}</b><span>Valor recebido</span><b class="tot">${brl(d.valor)}</b>`;
  $('#sheet').innerHTML = `<div class="s-bar"></div>
  <div class="s-head"><img src="/assets/logo.jpg" alt="">
    <div class="s-co"><h3>${EMP.nome}</h3><em>${EMP.tag}</em><small>CNPJ: ${EMP.cnpj}</small></div>
    <div class="s-val"><b>RECIBO DE PAGAMENTO</b><div><span>VALOR RECEBIDO</span><strong>${brl(d.valor)}</strong></div></div></div>
  <div class="s-hr"></div>
  <div class="s-box"><div class="s-lbl">REFERENTE A</div><div class="s-ref">${esc(d.descricao) || '—'}</div></div>
  <div class="s-two">
    <div class="s-box"><div class="s-lbl">DADOS DO RECEBEDOR</div><div class="s-kv"><b>Empresa:</b>${EMP.nome}</div><div class="s-kv"><b>Documento:</b>${EMP.cnpj}</div></div>
    <div class="s-box"><div class="s-lbl">DADOS DO PAGADOR</div><div class="s-kv"><b>Cliente:</b>${esc(d.cliente_nome) || '—'}</div><div class="s-kv"><b>Documento:</b>${esc(d.cliente_doc) || '—'}</div></div></div>
  <div class="s-box" style="margin-bottom:16px"><div class="s-lbl">DETALHES DO RECIBO</div>
    <table class="s-tbl"><tr><th>Data do pagamento</th><th>Status</th><th>Pedido</th><th>Valor do serviço</th><th>Desconto</th><th>Valor recebido</th></tr>
    <tr><td>${fdate(d.data_pagamento)}</td><td>${esc(d.status)}</td><td>${esc(d.pedido)}</td><td>${brl(d.valor_servico)}</td><td>${d.desconto > 0 ? '- ' + brl(d.desconto) : '—'}</td><td>${brl(d.valor)}</td></tr></table></div>
  <div class="s-box s-dec">Declaramos, para os devidos fins, que <b>${EMP.nome}</b> recebeu de <b>${esc(d.cliente_nome) || '—'}</b> a quantia de <b>${brl(d.valor)}</b>${d.desconto > 0 ? ` (serviço de ${brl(d.valor_servico)} com desconto de ${fmtPct(pctOf(d))}, equivalente a ${brl(d.desconto)})` : ''}, referente a <b>${esc(lowerFirst(d.descricao))}</b>, vinculada ao pedido <b>${esc(d.pedido)}</b>, na data de <b>${fdate(d.data_pagamento)}</b>.</div>
  <div class="s-sig"><div class="im"><img src="${sig}" alt="Assinatura"></div><div class="ln"></div><b>${EMP.nome}</b><small>Assinatura do responsável</small></div>
  <div class="s-foot">Este recibo foi gerado automaticamente e possui caráter comprobatório de recebimento.<br>${EMP.nome} | Documento emitido pelo sistema de recibos</div>`;
}
function fit() {
  const box = $('#previewBox'); if (!box.clientWidth) return;
  const s = box.clientWidth / 794; $('#sheet').style.transform = `scale(${s})`; box.style.height = 1123 * s + 'px';
}
window.addEventListener('resize', fit);

/* ---------- PDF (pdfmake: texto real, A4) ---------- */
let logoData;
async function getLogo() {
  if (logoData) return logoData;
  const img = new Image(); img.src = '/assets/logo.jpg'; await img.decode();
  const c = document.createElement('canvas'); c.width = c.height = 360;
  const x = c.getContext('2d'); x.fillStyle = '#fff'; x.fillRect(0, 0, 360, 360); x.drawImage(img, 0, 0, 360, 360);
  return (logoData = c.toDataURL('image/jpeg', 0.92));
}
let sigData;
async function getSig() {
  if (sigData) return sigData;
  const img = new Image(); img.src = sig; await img.decode();
  const c = document.createElement('canvas'); c.width = img.naturalWidth; c.height = img.naturalHeight;
  c.getContext('2d').drawImage(img, 0, 0);
  return (sigData = c.toDataURL('image/png'));
}
const fileName = d => `RECIBO_DSD_TECH_PEDIDO_${d.pedido}.pdf`;
async function makePdf(d) {
  d = full(d);
  const logo = await getLogo(), sigImg = await getSig(), N = '#0B2F5B', C = '#0AB4DC', G = '#E3E8F0', BG = '#F6F9FE';
  const box = (stack, fill = BG) => ({ table: { widths: ['*'], body: [[{ stack, margin: [12, 9, 12, 9] }]] },
    layout: { fillColor: () => fill, hLineColor: () => G, vLineColor: () => G, hLineWidth: () => 0.8, vLineWidth: () => 0.8 } });
  const lbl = t => ({ text: t, fontSize: 8, bold: true, color: C, characterSpacing: 1, margin: [0, 0, 0, 6] });
  const kv = (k, v) => ({ columns: [{ text: k, bold: true, width: 60 }, { text: v }], fontSize: 9.5, margin: [0, 2, 0, 2] });
  const th = t => ({ text: t, bold: true, color: N, fontSize: 9, fillColor: '#EEF3FC', margin: [4, 5, 4, 5] });
  const td = t => ({ text: t, fontSize: 9.5, margin: [4, 5, 4, 5] });
  const money = brl(d.valor), dt = fdate(d.data_pagamento);
  return pdfMake.createPdf({
    pageSize: 'A4', pageMargins: [40, 40, 40, 50], defaultStyle: { font: 'Roboto', fontSize: 10, color: '#1F2937' },
    info: { title: 'Recibo ' + d.pedido, author: EMP.nome },
    footer: () => ({ text: `${EMP.nome}  |  Documento emitido pelo sistema de recibos`, alignment: 'center', fontSize: 8, color: '#6B7280' }),
    content: [
      { canvas: [{ type: 'rect', x: 0, y: 0, w: 515, h: 5, color: N }], margin: [0, 0, 0, 12] },
      { columns: [
        { image: logo, width: 62 },
        { width: '*', margin: [10, 8, 0, 0], stack: [{ text: EMP.nome, fontSize: 15, bold: true, color: N }, { text: EMP.tag, italics: true, fontSize: 8.5, color: '#6B7280', margin: [0, 3, 0, 2] }, { text: 'CNPJ: ' + EMP.cnpj, fontSize: 8.5, color: '#6B7280' }] },
        { width: 150, stack: [{ text: 'RECIBO DE PAGAMENTO', bold: true, fontSize: 8.5, color: N, characterSpacing: 1.2, alignment: 'right', margin: [0, 0, 0, 6] },
          box([{ text: 'VALOR RECEBIDO', fontSize: 7.5, color: '#6B7280', alignment: 'right' }, { text: money, fontSize: 18, bold: true, color: N, alignment: 'right' }])] }
      ] },
      { canvas: [{ type: 'line', x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 0.8, lineColor: G }], margin: [0, 14, 0, 14] },
      box([lbl('REFERENTE A'), { text: d.descricao, fontSize: 13, bold: true, color: N }]),
      { columns: [box([lbl('DADOS DO RECEBEDOR'), kv('Empresa:', EMP.nome), kv('Documento:', EMP.cnpj)]), box([lbl('DADOS DO PAGADOR'), kv('Cliente:', d.cliente_nome), kv('Documento:', d.cliente_doc)])], columnGap: 12, margin: [0, 12, 0, 12] },
      box([lbl('DETALHES DO RECIBO'), { table: { widths: [64, 40, 44, '*', '*', '*'], body: [[th('Data'), th('Status'), th('Pedido'), th('Valor do serviço'), th('Desconto'), th('Valor recebido')], [td(dt), td(d.status), td(d.pedido), td(brl(d.valor_servico)), td(d.desconto > 0 ? '- ' + brl(d.desconto) : '—'), td(money)]] },
        layout: { hLineColor: () => G, vLineColor: () => G, hLineWidth: () => 0.8, vLineWidth: () => 0.8 } }]),
      { text: '', margin: [0, 6] },
      box([{ text: ['Declaramos, para os devidos fins, que ', { text: EMP.nome, bold: true }, ' recebeu de ', { text: d.cliente_nome, bold: true }, ' a quantia de ', { text: money, bold: true }, d.desconto > 0 ? ` (serviço de ${brl(d.valor_servico)} com desconto de ${fmtPct(pctOf(d))}, equivalente a ${brl(d.desconto)})` : '', ', referente a ', { text: lowerFirst(d.descricao), bold: true }, ', vinculada ao pedido ', { text: d.pedido, bold: true }, ', na data de ', { text: dt, bold: true }, '.'], lineHeight: 1.45, fontSize: 10 }]),
      { image: sigImg, fit: [160, 55], alignment: 'center', margin: [0, 28, 0, 0] },
      { canvas: [{ type: 'line', x1: 107, y1: 0, x2: 407, y2: 0, lineWidth: 0.8, lineColor: '#333' }], margin: [0, 4, 0, 5] },
      { text: EMP.nome, bold: true, alignment: 'center', color: N, fontSize: 10 },
      { text: 'Assinatura do responsável', alignment: 'center', color: '#6B7280', fontSize: 8.5, margin: [0, 4, 0, 24] },
      { canvas: [{ type: 'line', x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 0.8, lineColor: G, dash: { length: 3 } }] },
      { text: 'Este recibo foi gerado automaticamente e possui caráter comprobatório de recebimento.', alignment: 'center', fontSize: 8, color: '#6B7280', margin: [0, 8, 0, 0] }
    ]
  });
}
function openModal(pdf) {
  pdf.getBlob(b => { $('#pdfFrame').src = URL.createObjectURL(b); $('#pdfModal').showModal(); });
}
$('#closeModal').onclick = () => $('#pdfModal').close();

async function ensureSaved() {
  const d = readForm(), er = validate(d);
  if (showErrors(er)) { toast('Corrija os campos destacados.', true); return null; }
  try {
    const r = cur.id ? await api('/api/receipts/' + cur.id, { method: 'PUT', body: d }) : await api('/api/receipts', { method: 'POST', body: d });
    cur.id = r.id; F.doc.value = r.cliente_doc; return r;
  } catch (e) { if (e.field) showErrors({ [e.field]: e.message }); toast(e.message, true); return null; }
}
$('#bGen').onclick = async () => { const r = await ensureSaved(); if (r) { openModal(await makePdf(r)); toast('Recibo salvo e PDF gerado.'); } };
$('#bDown').onclick = async () => { const r = await ensureSaved(); if (r) (await makePdf(r)).download(fileName(r)); };
$('#bPrint').onclick = async () => { const r = await ensureSaved(); if (r) (await makePdf(r)).print(); };
$('#bEdit').onclick = () => { F.valor.focus(); F.valor.scrollIntoView({ behavior: 'smooth', block: 'center' }); toast('Edite os campos: a pré-visualização atualiza na hora.'); };
$('#bNew').onclick = newReceipt;

/* ---------- Bloqueio por senha ---------- */
const firstTime = !localStorage.getItem(VKEY);
$('#lockTitle').textContent = firstTime ? 'Crie sua senha de acesso' : 'Sistema bloqueado';
$('#lockMsg').textContent = firstTime ? 'Mínimo 8 caracteres. Seus recibos serão criptografados com ela. Se esquecer a senha, não há como recuperar os dados.' : 'Digite sua senha para abrir.';
$('#lockPw2').hidden = !firstTime;
let fails = 0, idle;
const lockNow = () => location.reload();
$('#lockNow').onclick = lockNow;
function startIdle() {
  const r = () => { clearTimeout(idle); idle = setTimeout(lockNow, 5 * 60 * 1000); };
  ['click', 'keydown', 'mousemove', 'touchstart'].forEach(ev => addEventListener(ev, r, { passive: true })); r();
}
$('#lockForm').onsubmit = async e => {
  e.preventDefault();
  const pw = $('#lockPw').value, err = $('#lockErr'); err.textContent = '';
  if (firstTime) {
    if (pw.length < 8) return (err.textContent = 'A senha precisa ter pelo menos 8 caracteres.');
    if (pw !== $('#lockPw2').value) return (err.textContent = 'As senhas não conferem.');
  }
  $('#lockBtn').disabled = true;
  try {
    await unlock(pw);
    $('#lock').hidden = true; document.body.classList.remove('locked'); $('#lockPw').value = ''; $('#lockPw2').value = '';
    startIdle(); loadDash(); render();
  } catch {
    fails++; err.textContent = 'Senha incorreta. Aguarde...';
    await new Promise(r => setTimeout(r, Math.min(30000, 1000 * 2 ** fails)));
    err.textContent = 'Senha incorreta.';
  }
  $('#lockBtn').disabled = false;
};
$('#lockPw').focus();
