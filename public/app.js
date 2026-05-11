'use strict';

/* ============================ helpers ============================ */
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === 'class') n.className = v;
    else if (k === 'html') n.innerHTML = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(n.dataset, v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    n.appendChild(typeof kid === 'string' ? document.createTextNode(kid) : kid);
  }
  return n;
};
const debounce = (fn, ms = 220) => {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
};

const CUR_SYMBOL = { USD:'$', ILS:'₪', ILA:'₪', EUR:'€', GBP:'£', GBp:'p', GBX:'p', JPY:'¥', CHF:'CHF ', CAD:'C$', AUD:'A$', HKD:'HK$' };
function curPrefix(cur) {
  if (!cur) return '';
  return CUR_SYMBOL[cur] || (cur + ' ');
}
function compact(v, maxFrac) {
  const abs = Math.abs(v);
  let div = 1, suf = '';
  if (abs >= 1e12) { div = 1e12; suf = 'T'; }
  else if (abs >= 1e9) { div = 1e9; suf = 'B'; }
  else if (abs >= 1e6) { div = 1e6; suf = 'M'; }
  else if (abs >= 1e3) { div = 1e3; suf = 'K'; }
  const n = v / div;
  const digits = maxFrac != null ? maxFrac : (Math.abs(n) >= 100 ? 0 : Math.abs(n) >= 10 ? 1 : 2);
  return n.toLocaleString('en-US', { maximumFractionDigits: digits }) + suf;
}
function fmtMoney(v, cur) {
  if (v == null || !isFinite(v)) return '—';
  if (Math.abs(v) < 1000) {
    const d = Math.abs(v) < 1 ? 4 : 2;
    return curPrefix(cur) + v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: d });
  }
  return curPrefix(cur) + compact(v);
}
function fmtPrice(v, cur) {
  if (v == null || !isFinite(v)) return '—';
  const d = Math.abs(v) < 1 ? 4 : 2;
  return curPrefix(cur) + v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: d });
}
function fmtPct(frac, digits = 2) {
  if (frac == null || !isFinite(frac)) return '—';
  return (frac * 100).toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits }) + '%';
}
function fmtRatio(v) { return v == null || !isFinite(v) ? '—' : v.toLocaleString('en-US', { maximumFractionDigits: 2 }); }
function fmtInt(v) {
  if (v == null || !isFinite(v)) return '—';
  if (Math.abs(v) >= 1e5) return compact(v);
  return Math.round(v).toLocaleString('en-US');
}
function fmtDate(s) { return s || '—'; }
function fmtMetric(v, fmt) {
  if (!fmt) return String(v);
  switch (fmt.type) {
    case 'money': return fmtMoney(v, fmt.currency);
    case 'price': return fmtPrice(v, fmt.currency);
    case 'percent': return fmtPct(v);
    case 'ratio': return fmtRatio(v);
    case 'int': return fmtInt(v);
    case 'date': return fmtDate(v);
    default: return String(v);
  }
}
function shortDate(iso) { // YYYY-MM-DD -> "Mar 2024" or "31 Mar 24"
  if (!iso) return '';
  const m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const [y, mo, d] = iso.split('-').map(Number);
  if (!mo) return iso;
  return `${m[mo - 1]} ’${String(y).slice(2)}`;
}
function tsLabel(ms, range) {
  const d = new Date(ms);
  const m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  if (range === '1d' || range === '5d') return `${d.getDate()} ${m[d.getMonth()]} ${d.getHours()}:${String(d.getMinutes()).padStart(2,'0')}`;
  if (range === '1mo' || range === '3mo' || range === '6mo' || range === 'ytd') return `${d.getDate()} ${m[d.getMonth()]}`;
  if (range === 'max' || range === '10y') return `${m[d.getMonth()]} ${d.getFullYear()}`;
  return `${m[d.getMonth()]} ’${String(d.getFullYear()).slice(2)}`;
}

async function api(path) {
  const r = await fetch(path, { headers: { Accept: 'application/json' } });
  let body = null;
  try { body = await r.json(); } catch { /* */ }
  if (!r.ok) throw new Error((body && body.error) || `Request failed (${r.status})`);
  return body;
}
function toast(msg, ms = 2600) {
  const t = $('#toast');
  t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add('hidden'), ms);
}

/* ============================ state ============================ */
const State = { companies: [], sectors: [], activeSector: null, charts: [] };
const CHART_COLORS = ['#38bdf8','#a78bfa','#34d399','#fbbf24','#fb7185','#22d3ee','#f97316','#94a3b8'];

function destroyCharts() { State.charts.forEach((c) => { try { c.destroy(); } catch {} }); State.charts = []; }
function chartReady() { return typeof window.Chart !== 'undefined'; }
function newChart(canvas, cfg) {
  if (!chartReady()) return null;
  const c = new Chart(canvas.getContext('2d'), cfg);
  State.charts.push(c);
  return c;
}

if (chartReady()) {
  Chart.defaults.color = '#93a1b5';
  Chart.defaults.borderColor = 'rgba(36,48,68,.7)';
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.plugins.legend.labels.boxWidth = 12;
  Chart.defaults.plugins.legend.labels.boxHeight = 12;
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.maintainAspectRatio = false;
}

/* ============================ search ============================ */
const searchEl = $('#search');
const suggestEl = $('#suggest');
let suggItems = [];
let suggActive = -1;

function hideSuggest() { suggestEl.classList.add('hidden'); suggestEl.innerHTML = ''; suggItems = []; suggActive = -1; }

function renderSuggest(data) {
  suggestEl.innerHTML = '';
  suggItems = [];
  const mk = (sym, name, ex) => {
    const item = el('div', { class: 'item', onclick: () => { hideSuggest(); searchEl.blur(); goReport(sym); } },
      el('span', { class: 'tk', text: sym }),
      el('span', { class: 'nm', text: name }),
      el('span', { class: 'ex', text: ex || '' }),
    );
    suggestEl.appendChild(item);
    suggItems.push({ sym, node: item });
  };
  const dir = data.directory || [];
  const ext = data.external || [];
  if (!dir.length && !ext.length) {
    suggestEl.appendChild(el('div', { class: 'empty', text: `No matches for “${data.query}”. Try a ticker — TASE tickers end in .TA (e.g. POLI.TA).` }));
    suggestEl.classList.remove('hidden');
    return;
  }
  if (dir.length) {
    suggestEl.appendChild(el('div', { class: 'grp', text: 'Israeli companies directory' }));
    dir.slice(0, 20).forEach((c) => mk(c.symbol, c.name + (c.hebrew ? '  ·  ' + c.hebrew : ''), c.exchange));
  }
  if (ext.length) {
    suggestEl.appendChild(el('div', { class: 'grp', text: 'Other matches (Yahoo Finance)' }));
    ext.forEach((c) => mk(c.symbol, c.name, c.exchange + (c.type ? ' · ' + c.type : '')));
  }
  suggestEl.classList.remove('hidden');
}

const doSearch = debounce(async (q) => {
  if (!q || q.length < 1) { hideSuggest(); return; }
  try {
    const data = await api('/api/search?q=' + encodeURIComponent(q));
    if (searchEl.value.trim() === q.trim()) renderSuggest(data);
  } catch { hideSuggest(); }
}, 200);

searchEl.addEventListener('input', () => {
  const q = searchEl.value.trim();
  // also live-filter the home list by text
  if (!isReportOpen()) renderCompanyList();
  doSearch(q);
});
searchEl.addEventListener('focus', () => { const q = searchEl.value.trim(); if (q) doSearch(q); });
searchEl.addEventListener('keydown', (e) => {
  if (suggestEl.classList.contains('hidden')) {
    if (e.key === 'Enter') {
      const q = searchEl.value.trim();
      if (/^[A-Za-z0-9.\-^=]{1,20}$/.test(q)) { hideSuggest(); searchEl.blur(); goReport(q.toUpperCase()); }
    }
    return;
  }
  if (e.key === 'ArrowDown') { e.preventDefault(); moveSugg(1); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); moveSugg(-1); }
  else if (e.key === 'Enter') {
    e.preventDefault();
    if (suggActive >= 0 && suggItems[suggActive]) { const s = suggItems[suggActive].sym; hideSuggest(); searchEl.blur(); goReport(s); }
    else { const q = searchEl.value.trim(); if (q) { hideSuggest(); searchEl.blur(); goReport(q.toUpperCase()); } }
  } else if (e.key === 'Escape') { hideSuggest(); }
});
function moveSugg(d) {
  if (!suggItems.length) return;
  if (suggActive >= 0) suggItems[suggActive].node.classList.remove('active');
  suggActive = (suggActive + d + suggItems.length) % suggItems.length;
  const it = suggItems[suggActive];
  it.node.classList.add('active');
  it.node.scrollIntoView({ block: 'nearest' });
}
document.addEventListener('click', (e) => {
  if (!suggestEl.contains(e.target) && e.target !== searchEl) hideSuggest();
});

/* ============================ home view ============================ */
function isReportOpen() { return !$('#report').classList.contains('hidden'); }

async function loadDirectory() {
  try {
    const [sec, cos] = await Promise.all([api('/api/sectors'), api('/api/companies')]);
    State.sectors = sec.sectors || [];
    State.companies = (cos.companies || []);
    if (sec.taseHubEnabled) $('#dataSources').textContent = 'TASE Data Hub (official securities list) + Yahoo Finance (delayed quotes & fundamentals)';
    $('#homeSub').textContent = `Browse ${sec.total} companies by sector, or search above. Each company opens a full, visual financial report — objective data only, no buy/sell scoring.`;
    renderSectorChips();
    renderCompanyList();
  } catch (e) {
    $('#companyList').innerHTML = '';
    $('#companyList').appendChild(el('div', { class: 'nodata', text: 'Could not load the company directory: ' + e.message }));
  }
}

function renderSectorChips() {
  const wrap = $('#sectorChips');
  wrap.innerHTML = '';
  const all = el('button', { class: 'chip' + (State.activeSector ? '' : ' active'), onclick: () => { State.activeSector = null; renderSectorChips(); renderCompanyList(); } },
    'All sectors', el('span', { class: 'n', text: String(State.companies.length) }));
  wrap.appendChild(all);
  for (const s of State.sectors) {
    wrap.appendChild(el('button', { class: 'chip' + (State.activeSector === s.sector ? ' active' : ''), onclick: () => { State.activeSector = (State.activeSector === s.sector ? null : s.sector); renderSectorChips(); renderCompanyList(); } },
      s.sector, el('span', { class: 'n', text: String(s.count) })));
  }
}

function renderCompanyList() {
  const q = searchEl.value.trim().toLowerCase();
  const list = State.companies.filter((c) => {
    if (State.activeSector && c.sector !== State.activeSector) return false;
    if (q) return c.symbol.toLowerCase().includes(q) || c.name.toLowerCase().includes(q) || (c.hebrew && c.hebrew.includes(searchEl.value.trim()));
    return true;
  });
  $('#companyCount').textContent = `${list.length} compan${list.length === 1 ? 'y' : 'ies'}${State.activeSector ? ' in ' + State.activeSector : ''}${q ? ' matching “' + searchEl.value.trim() + '”' : ''}`;
  const wrap = $('#companyList');
  wrap.innerHTML = '';
  if (!list.length) { wrap.appendChild(el('div', { class: 'nodata', text: 'No companies match. You can still search any ticker directly above.' })); return; }
  const frag = document.createDocumentFragment();
  for (const c of list.slice(0, 600)) {
    frag.appendChild(el('div', { class: 'co', onclick: () => goReport(c.symbol) },
      el('span', { class: 'tk', text: c.symbol }),
      el('div', { class: 'meta' },
        el('div', { class: 'nm', text: c.name }),
        el('div', { class: 'sub', text: (c.hebrew ? c.hebrew + ' · ' : '') + c.sector }),
      ),
      el('span', { class: 'badge', text: c.exchange || '' }),
    ));
  }
  wrap.appendChild(frag);
  if (list.length > 600) wrap.appendChild(el('div', { class: 'muted small', text: `Showing first 600 of ${list.length}. Refine with the search box.` }));
}

/* ============================ routing ============================ */
function goReport(symbol) {
  const s = String(symbol).toUpperCase();
  if (location.hash !== '#/co/' + s) location.hash = '#/co/' + s;
  else openReport(s);
}
function goHome() { if (location.hash) location.hash = ''; else showHome(); }
window.addEventListener('hashchange', route);
function route() {
  const m = location.hash.match(/^#\/co\/([^/]+)$/);
  if (m) openReport(decodeURIComponent(m[1]).toUpperCase());
  else showHome();
}
function showHome() {
  destroyCharts();
  $('#report').classList.add('hidden');
  $('#report').innerHTML = '';
  $('#home').classList.remove('hidden');
  document.title = 'Pasten · Israeli companies financial explorer';
  window.scrollTo(0, 0);
}
$('#brandHome').addEventListener('click', goHome);
$('#brandHome').addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') goHome(); });

/* ============================ report view ============================ */
async function openReport(symbol) {
  hideSuggest();
  $('#home').classList.add('hidden');
  const host = $('#report');
  host.classList.remove('hidden');
  destroyCharts();
  host.innerHTML = '';
  host.appendChild(el('div', { class: 'linkback', onclick: goHome }, '←', ' Back to directory'));
  host.appendChild(el('div', { class: 'loading-wrap' }, el('span', { class: 'spinner' }), ' Loading ' + symbol + ' …'));
  window.scrollTo(0, 0);
  document.title = symbol + ' · Pasten';
  try {
    const data = await api('/api/company/' + encodeURIComponent(symbol));
    renderReport(host, data);
    document.title = (data.profile?.longName || symbol) + ' · Pasten';
  } catch (e) {
    host.innerHTML = '';
    host.appendChild(el('div', { class: 'linkback', onclick: goHome }, '←', ' Back to directory'));
    host.appendChild(el('div', { class: 'card' },
      el('h2', { text: 'Couldn’t load ' + symbol }),
      el('p', { class: 'muted', text: e.message }),
      el('p', { class: 'small muted', text: 'Tip: Tel Aviv Stock Exchange tickers use the .TA suffix (e.g. POLI.TA for Bank Hapoalim, BEZQ.TA for Bezeq). Many large Israeli companies are also listed in the US under their own ticker (e.g. TEVA, NICE, CYBR).' }),
    ));
  }
}

function renderReport(host, d) {
  destroyCharts();
  host.innerHTML = '';
  const cur = d.currency || d.quote?.currency || '';
  const q = d.quote || {};

  host.appendChild(el('div', { class: 'linkback', onclick: goHome }, '←', ' Back to directory'));

  /* ---- header ---- */
  const price = q.price, prev = q.previousClose;
  const chg = (price != null && prev != null) ? price - prev : q.change;
  const chgFrac = (price != null && prev != null && prev !== 0) ? (price - prev) / prev : null;
  const chgCls = chg == null ? 'flat' : chg > 0 ? 'pos' : chg < 0 ? 'neg' : 'flat';
  const chgSign = chg > 0 ? '+' : '';
  const tags = [];
  if (d.profile?.exchangeName) tags.push(d.profile.exchangeName);
  if (d.profile?.sector) tags.push(d.profile.sector);
  if (d.profile?.industry) tags.push(d.profile.industry);
  if (d.directory?.source === 'tase-data-hub') tags.push('TASE-listed');

  const rangeBar = (() => {
    const lo = q.fiftyTwoWeekLow, hi = q.fiftyTwoWeekHigh, p = q.price;
    if (lo == null || hi == null || p == null || hi <= lo) return null;
    const pos = Math.max(0, Math.min(1, (p - lo) / (hi - lo)));
    return el('div', { class: 'rangebar' },
      el('div', { class: 'track' }, el('div', { class: 'mark', style: `left:calc(${(pos * 100).toFixed(1)}% - 1px)` })),
      el('div', { class: 'lbls' }, el('span', { text: '52-wk low ' + fmtPrice(lo, cur) }), el('span', { text: '52-wk high ' + fmtPrice(hi, cur) })),
    );
  })();

  host.appendChild(el('div', { class: 'card rep-head' },
    el('div', { class: 'spread' },
      el('div', {},
        el('div', { class: 'name', text: d.profile?.longName || d.symbol }),
        d.profile?.hebrewName ? el('div', { class: 'he', text: d.profile.hebrewName }) : null,
        el('div', { class: 'tags' },
          el('span', { class: 'tag', text: d.symbol }),
          ...tags.map((t) => el('span', { class: 'tag', text: t })),
        ),
      ),
      el('div', { style: 'text-align:right' },
        el('div', { class: 'price-big' }, fmtPrice(q.price, cur), el('span', { class: 'price-cur', text: cur || '' })),
        el('div', { class: 'chg ' + chgCls, text: chg == null ? 'No live quote' : `${chgSign}${fmtPrice(chg, cur)}${chgFrac != null ? `  (${chgSign}${fmtPct(chgFrac)})` : ''}` }),
        q.marketState && q.marketState !== 'REGULAR' ? el('div', { class: 'small muted', text: 'Market: ' + q.marketState }) : null,
      ),
    ),
    rangeBar,
    el('div', { class: 'pillrow' },
      pill('Market cap', fmtMoney(q.marketCap, cur)),
      pill('Prev close', fmtPrice(q.previousClose, cur)),
      pill('Open', fmtPrice(q.open, cur)),
      pill('Day range', q.dayLow != null ? `${fmtPrice(q.dayLow, cur)} – ${fmtPrice(q.dayHigh, cur)}` : '—'),
      d.profile?.website ? el('a', { class: 'pill', href: d.profile.website, target: '_blank', rel: 'noopener', text: 'Website ↗' }) : null,
    ),
    el('div', { class: 'small muted', style: 'margin-top:8px', text: 'As of ' + new Date(d.asOf).toLocaleString() + ' · prices and fundamentals are delayed.' }),
  ));

  if (d.warnings && d.warnings.length) {
    host.appendChild(el('div', { class: 'warn-banner' }, 'Some data could not be retrieved: ' + d.warnings.join(' · ')));
  }

  /* ---- section nav ---- */
  const sections = [
    ['snapshot', 'Snapshot'],
    ['price', 'Price'],
    ['revenue', 'Revenue & profit'],
    ['margins', 'Margins'],
    ['cashflow', 'Cash flow'],
    ['balance', 'Balance sheet'],
    ['eps', 'EPS'],
    ['statements', 'Statements'],
    ['analysts', 'Analysts'],
    ['about', 'About'],
  ];
  host.appendChild(el('nav', { class: 'secnav' }, ...sections.map(([id, label]) =>
    el('a', { href: '#sec-' + id, onclick: (e) => { e.preventDefault(); const t = document.getElementById('sec-' + id); if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' }); } }, label))));

  /* ---- snapshot metrics ---- */
  host.appendChild(sectionAnchor('snapshot'));
  const groups = {};
  for (const m of (d.metrics || [])) (groups[m.group] = groups[m.group] || []).push(m);
  const order = ['Valuation','Profitability & margins','Growth','Income statement (TTM)','Balance sheet & liquidity','Cash flow (TTM)','Dividends','Market & trading','Shares & ownership','Analyst coverage','Key dates'];
  const groupNames = [...new Set([...order.filter((g) => groups[g]), ...Object.keys(groups)])];
  const mg = el('div', { class: 'metric-groups' });
  for (const g of groupNames) {
    const card = el('div', { class: 'mg' }, el('h3', { text: g }));
    for (const m of groups[g]) {
      const row = el('div', { class: 'm' },
        el('div', { class: 'topline' }, el('span', { class: 'lbl', text: m.label }), el('span', { class: 'val', text: fmtMetric(m.value, m.format) })),
        el('div', { class: 'help', text: m.help || '' }),
      );
      row.addEventListener('click', () => row.classList.toggle('open'));
      card.appendChild(row);
    }
    mg.appendChild(card);
  }
  host.appendChild(el('div', {},
    el('h2', { text: 'Snapshot — key figures' }),
    el('p', { class: 'small muted', style: 'margin-top:-6px', text: 'Tap any item for a plain-English definition. These are objective metrics straight from the financial data — no scoring.' }),
    mg,
  ));

  /* ---- price chart ---- */
  host.appendChild(sectionAnchor('price'));
  host.appendChild(buildPriceChartCard(d, cur));

  /* ---- revenue & profit ---- */
  host.appendChild(sectionAnchor('revenue'));
  host.appendChild(buildRevenueCard(d, cur));

  /* ---- margins ---- */
  host.appendChild(sectionAnchor('margins'));
  host.appendChild(buildMarginsCard(d));

  /* ---- cash flow ---- */
  host.appendChild(sectionAnchor('cashflow'));
  host.appendChild(buildCashflowCard(d, cur));

  /* ---- balance sheet ---- */
  host.appendChild(sectionAnchor('balance'));
  host.appendChild(buildBalanceCard(d, cur));

  /* ---- EPS ---- */
  host.appendChild(sectionAnchor('eps'));
  host.appendChild(buildEpsCard(d, cur));

  /* ---- statements ---- */
  host.appendChild(sectionAnchor('statements'));
  host.appendChild(el('h2', { text: 'Financial statements' }));
  host.appendChild(buildStatementCard('Income statement', d.statements?.income, cur));
  host.appendChild(buildStatementCard('Balance sheet', d.statements?.balance, cur));
  host.appendChild(buildStatementCard('Cash flow statement', d.statements?.cashflow, cur));

  /* ---- analysts ---- */
  host.appendChild(sectionAnchor('analysts'));
  host.appendChild(buildAnalystCard(d, cur));

  /* ---- about ---- */
  host.appendChild(sectionAnchor('about'));
  host.appendChild(buildAboutCard(d, cur));

  // render charts now that nodes are in the DOM
  setTimeout(() => renderAllCharts(d, cur), 0);
}

function pill(label, val) { return el('span', { class: 'pill' }, label + ': ', el('b', { text: val })); }
function sectionAnchor(id) { return el('div', { id: 'sec-' + id, style: 'height:0;scroll-margin-top:140px' }); }
function chartBox(id, tall) { return el('div', { class: 'chart-box' + (tall ? ' tall' : '') }, el('canvas', { id })); }
function noData(msg) { return el('div', { class: 'nodata', text: msg || 'No data available for this company.' }); }

/* ---- price chart card ---- */
const RANGES = [['1mo','1M'],['6mo','6M'],['ytd','YTD'],['1y','1Y'],['5y','5Y'],['max','Max']];
function buildPriceChartCard(d, cur) {
  const card = el('div', { class: 'chart-card' });
  const btns = el('div', { class: 'range-btns' });
  card.appendChild(el('div', { class: 'spread' }, el('h2', { text: 'Share price' }), btns));
  const box = chartBox('chart-price', true);
  card.appendChild(box);
  card.appendChild(el('div', { class: 'legend-note', text: 'Closing price (adjusted for splits & dividends where available). Source: Yahoo Finance, delayed.' }));
  let activeBtn = null;
  RANGES.forEach(([r, label]) => {
    const b = el('button', { class: 'btn small' + (r === '1y' ? ' active' : ''), text: label, onclick: async () => {
      if (activeBtn) activeBtn.classList.remove('active');
      b.classList.add('active'); activeBtn = b;
      await loadPrice(r);
    } });
    if (r === '1y') activeBtn = b;
    btns.appendChild(b);
  });
  async function loadPrice(range) {
    let pts = null, meta = null;
    if (range === '1y' && d.price1y && d.price1y.points && d.price1y.points.length) { pts = d.price1y.points; meta = d.price1y.meta; }
    else {
      try { const r = await api(`/api/history/${encodeURIComponent(d.symbol)}?range=${range}`); pts = r.points; meta = r.meta; }
      catch (e) { toast('Price history unavailable: ' + e.message); return; }
    }
    drawPrice(pts, range);
  }
  function drawPrice(points, range) {
    const cv = $('#chart-price');
    if (!cv || !chartReady()) return;
    // destroy prior price chart instance
    const prev = State.charts.find((c) => c.canvas === cv);
    if (prev) { prev.destroy(); State.charts = State.charts.filter((c) => c !== prev); }
    if (!points || !points.length) { cv.parentElement.innerHTML = ''; cv.parentElement.appendChild(noData('No price history.')); return; }
    const labels = points.map((p) => tsLabel(p.t, range));
    const data = points.map((p) => p.adjclose != null ? p.adjclose : p.close);
    const up = data[data.length - 1] >= data[0];
    const color = up ? '#34d399' : '#f87171';
    newChart(cv, {
      type: 'line',
      data: { labels, datasets: [{ label: 'Close (' + cur + ')', data, borderColor: color, backgroundColor: (color + '22'), fill: true, pointRadius: 0, borderWidth: 2, tension: 0.12 }] },
      options: {
        interaction: { mode: 'index', intersect: false },
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ' ' + fmtPrice(c.parsed.y, cur) } } },
        scales: {
          x: { ticks: { maxTicksLimit: 7, autoSkip: true, maxRotation: 0 }, grid: { display: false } },
          y: { ticks: { callback: (v) => fmtPrice(v, cur) }, grid: { color: 'rgba(36,48,68,.4)' } },
        },
      },
    });
  }
  // initial draw deferred until charts pass
  card._draw = () => loadPrice('1y');
  return card;
}

/* ---- revenue & profit ---- */
function buildRevenueCard(d, cur) {
  const card = el('div', { class: 'chart-card' });
  card.appendChild(el('div', { class: 'spread' }, el('h2', { text: 'Revenue & profit by fiscal year' }), el('span', { class: 'small muted', text: cur ? 'in ' + cur : '' })));
  const series = d.series?.revenue || [];
  if (!series.length) { card.appendChild(noData('No annual income-statement data available.')); return card; }
  card.appendChild(chartBox('chart-rev'));
  card.appendChild(el('div', { class: 'legend-note', text: 'From reported annual income statements. Gross profit / operating income may be unavailable for banks & insurers (different statement structure).' }));
  card._draw = () => {
    const cv = $('#chart-rev'); if (!cv || !chartReady()) return;
    const labels = series.map((s) => s.period);
    const ds = [
      mkBar('Revenue', series.map((s) => s.revenue), CHART_COLORS[0]),
      mkBar('Gross profit', series.map((s) => s.grossProfit), CHART_COLORS[5]),
      mkBar('Operating income', series.map((s) => s.operatingIncome), CHART_COLORS[1]),
      mkBar('Net income', series.map((s) => s.netIncome), CHART_COLORS[2]),
    ].filter((x) => x.data.some((v) => v != null));
    newChart(cv, { type: 'bar', data: { labels, datasets: ds }, options: barOpts(cur) });
  };
  return card;
}

/* ---- margins ---- */
function buildMarginsCard(d) {
  const card = el('div', { class: 'chart-card' });
  card.appendChild(el('div', { class: 'spread' }, el('h2', { text: 'Profit margins over time' }), el('span', { class: 'small muted', text: '% of revenue' })));
  const series = (d.series?.margins || []).filter((s) => s.gross != null || s.operating != null || s.net != null);
  if (!series.length) { card.appendChild(noData('No margin history available.')); return card; }
  card.appendChild(chartBox('chart-margin'));
  card._draw = () => {
    const cv = $('#chart-margin'); if (!cv || !chartReady()) return;
    const labels = series.map((s) => s.period);
    const line = (label, key, color) => ({ label, data: series.map((s) => s[key] == null ? null : s[key] * 100), borderColor: color, backgroundColor: color + '22', borderWidth: 2, pointRadius: 3, tension: 0.15, spanGaps: true });
    const ds = [line('Gross margin', 'gross', CHART_COLORS[5]), line('Operating margin', 'operating', CHART_COLORS[1]), line('Net margin', 'net', CHART_COLORS[2])].filter((x) => x.data.some((v) => v != null));
    newChart(cv, { type: 'line', data: { labels, datasets: ds }, options: {
      interaction: { mode: 'index', intersect: false },
      plugins: { tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${c.parsed.y == null ? '—' : c.parsed.y.toFixed(1) + '%'}` } } },
      scales: { x: { grid: { display: false } }, y: { ticks: { callback: (v) => v + '%' }, grid: { color: 'rgba(36,48,68,.4)' } } },
    } });
  };
  return card;
}

/* ---- cash flow ---- */
function buildCashflowCard(d, cur) {
  const card = el('div', { class: 'chart-card' });
  card.appendChild(el('div', { class: 'spread' }, el('h2', { text: 'Cash flow by fiscal year' }), el('span', { class: 'small muted', text: cur ? 'in ' + cur : '' })));
  const series = d.series?.cashflow || [];
  if (!series.length) { card.appendChild(noData('No annual cash-flow data available.')); return card; }
  card.appendChild(chartBox('chart-cf'));
  card.appendChild(el('div', { class: 'legend-note', text: 'Free cash flow ≈ operating cash flow + capital expenditures (capex is reported as a negative number).' }));
  card._draw = () => {
    const cv = $('#chart-cf'); if (!cv || !chartReady()) return;
    const labels = series.map((s) => s.period);
    const ds = [
      mkBar('Operating', series.map((s) => s.operating), CHART_COLORS[0]),
      mkBar('Investing', series.map((s) => s.investing), CHART_COLORS[4]),
      mkBar('Financing', series.map((s) => s.financing), CHART_COLORS[1]),
      { type: 'line', label: 'Free cash flow', data: series.map((s) => s.freeCashFlow), borderColor: CHART_COLORS[2], backgroundColor: CHART_COLORS[2], borderWidth: 2, pointRadius: 3, tension: 0.15, spanGaps: true },
    ].filter((x) => (x.data || []).some((v) => v != null));
    newChart(cv, { type: 'bar', data: { labels, datasets: ds }, options: barOpts(cur) });
  };
  return card;
}

/* ---- balance sheet ---- */
function buildBalanceCard(d, cur) {
  const card = el('div', { class: 'chart-card' });
  card.appendChild(el('div', { class: 'spread' }, el('h2', { text: 'Balance sheet by fiscal year' }), el('span', { class: 'small muted', text: cur ? 'in ' + cur : '' })));
  const series = d.series?.balance || [];
  if (!series.length) { card.appendChild(noData('No annual balance-sheet data available.')); return card; }
  card.appendChild(chartBox('chart-bs'));
  card.appendChild(el('div', { style: 'height:8px' }));
  card.appendChild(chartBox('chart-bs2'));
  card.appendChild(el('div', { class: 'legend-note', text: 'Top: total assets vs. total liabilities vs. shareholders equity. Bottom: cash & equivalents vs. total debt.' }));
  card._draw = () => {
    const labels = series.map((s) => s.period);
    const cv1 = $('#chart-bs');
    if (cv1 && chartReady()) {
      const ds1 = [
        mkBar('Total assets', series.map((s) => s.totalAssets), CHART_COLORS[0]),
        mkBar('Total liabilities', series.map((s) => s.totalLiabilities), CHART_COLORS[4]),
        mkBar('Shareholders equity', series.map((s) => s.totalEquity), CHART_COLORS[2]),
      ].filter((x) => x.data.some((v) => v != null));
      newChart(cv1, { type: 'bar', data: { labels, datasets: ds1 }, options: barOpts(cur) });
    }
    const cv2 = $('#chart-bs2');
    if (cv2 && chartReady()) {
      const ds2 = [
        mkBar('Cash & equivalents', series.map((s) => s.cash), CHART_COLORS[6]),
        mkBar('Total debt', series.map((s) => s.totalDebt), CHART_COLORS[7]),
      ].filter((x) => x.data.some((v) => v != null));
      if (ds2.length) newChart(cv2, { type: 'bar', data: { labels, datasets: ds2 }, options: barOpts(cur) });
      else cv2.parentElement.remove();
    }
  };
  return card;
}

/* ---- EPS ---- */
function buildEpsCard(d, cur) {
  const card = el('div', { class: 'chart-card' });
  card.appendChild(el('div', { class: 'spread' }, el('h2', { text: 'Earnings per share — actual vs. estimate' }), el('span', { class: 'small muted', text: 'per quarter' })));
  const series = (d.series?.eps || []).filter((s) => s.actual != null || s.estimate != null);
  if (!series.length) {
    // fall back to annual earnings (net income) if EPS unavailable
    const ey = (d.series?.earningsYearly || []).filter((s) => s.earnings != null);
    if (!ey.length) { card.appendChild(noData('No EPS / earnings history available.')); return card; }
    card.querySelector('h2').textContent = 'Net income by fiscal year';
    card.querySelector('.small.muted').textContent = cur ? 'in ' + cur : '';
    card.appendChild(chartBox('chart-eps'));
    card._draw = () => { const cv = $('#chart-eps'); if (!cv || !chartReady()) return;
      newChart(cv, { type: 'bar', data: { labels: ey.map((s) => s.period), datasets: [mkBar('Net income', ey.map((s) => s.earnings), CHART_COLORS[2]), mkBar('Revenue', ey.map((s) => s.revenue), CHART_COLORS[0])].filter((x) => x.data.some((v) => v != null)) }, options: barOpts(cur) }); };
    return card;
  }
  card.appendChild(chartBox('chart-eps'));
  card.appendChild(el('div', { class: 'legend-note', text: 'Reported (actual) EPS vs. the analyst consensus estimate for that quarter. A bar above the estimate is an earnings “beat”.' }));
  card._draw = () => {
    const cv = $('#chart-eps'); if (!cv || !chartReady()) return;
    const labels = series.map((s) => shortDate(s.period));
    newChart(cv, { type: 'bar', data: { labels, datasets: [
      mkBar('Estimate EPS', series.map((s) => s.estimate), CHART_COLORS[7]),
      mkBar('Actual EPS', series.map((s) => s.actual), CHART_COLORS[0]),
    ].filter((x) => x.data.some((v) => v != null)) }, options: {
      plugins: { tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${c.parsed.y == null ? '—' : fmtPrice(c.parsed.y, cur)}` } } },
      scales: { x: { grid: { display: false } }, y: { ticks: { callback: (v) => fmtPrice(v, cur) }, grid: { color: 'rgba(36,48,68,.4)' } } },
    } });
  };
  return card;
}

/* ---- statements table ---- */
function buildStatementCard(title, block, cur) {
  const card = el('div', { class: 'card tight' });
  const head = el('div', { class: 'collapse-h open' }, el('h2', { text: title, style: 'margin:0' }), el('span', { class: 'caret', text: '▸' }));
  card.appendChild(head);
  const body = el('div', { style: 'margin-top:10px' });
  card.appendChild(body);
  head.addEventListener('click', () => { head.classList.toggle('open'); body.style.display = head.classList.contains('open') ? '' : 'none'; });
  if (!block || (!(block.annual || []).length && !(block.quarterly || []).length)) { body.appendChild(noData('Not reported for this company (common for banks, insurers and partnerships).')); return card; }
  let mode = (block.annual || []).length ? 'annual' : 'quarterly';
  const toggle = el('div', { class: 'range-btns', style: 'margin-bottom:8px' });
  const tableWrap = el('div', { class: 'table-scroll' });
  const bA = el('button', { class: 'btn small' + (mode === 'annual' ? ' active' : ''), text: 'Annual' });
  const bQ = el('button', { class: 'btn small' + (mode === 'quarterly' ? ' active' : ''), text: 'Quarterly' });
  bA.addEventListener('click', () => { mode = 'annual'; bA.classList.add('active'); bQ.classList.remove('active'); render(); });
  bQ.addEventListener('click', () => { mode = 'quarterly'; bQ.classList.add('active'); bA.classList.remove('active'); render(); });
  if ((block.annual || []).length) toggle.appendChild(bA);
  if ((block.quarterly || []).length) toggle.appendChild(bQ);
  body.appendChild(toggle);
  body.appendChild(tableWrap);
  function render() {
    const rows = (mode === 'annual' ? block.annual : block.quarterly).slice(-6).reverse(); // most recent first, up to 6
    const labels = block.fieldLabels || {};
    const fields = Object.keys(labels);
    const table = el('table', { class: 'fin' });
    const thead = el('thead'); const trh = el('tr'); trh.appendChild(el('th', { text: mode === 'annual' ? 'Fiscal year' : 'Quarter ending' }));
    rows.forEach((r) => trh.appendChild(el('th', { text: mode === 'annual' ? r.date.slice(0, 4) : r.date })));
    thead.appendChild(trh); table.appendChild(thead);
    const tbody = el('tbody');
    for (const f of fields) {
      if (rows.every((r) => r.fields[f] == null)) continue;
      const tr = el('tr'); tr.appendChild(el('td', { text: labels[f] }));
      rows.forEach((r) => tr.appendChild(el('td', { text: r.fields[f] == null ? '—' : fmtMoney(r.fields[f], cur) })));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    tableWrap.innerHTML = ''; tableWrap.appendChild(table);
  }
  render();
  return card;
}

/* ---- analysts ---- */
function buildAnalystCard(d, cur) {
  const card = el('div', { class: 'card' });
  card.appendChild(el('h2', { text: 'Analyst coverage (raw consensus data)' }));
  card.appendChild(el('p', { class: 'small muted', style: 'margin-top:-4px', text: 'Shown for completeness. These figures are produced by third-party analysts, not by this tool — Pasten does not rate or recommend anything.' }));
  const a = d.analyst || {};
  const q = d.quote || {};
  // price-target bar
  const lo = d.metrics?.find((m) => m.label === 'Low price target')?.value;
  const mean = d.metrics?.find((m) => m.label === 'Mean price target')?.value;
  const hi = d.metrics?.find((m) => m.label === 'High price target')?.value;
  if (lo != null && hi != null && hi > lo) {
    const cp = q.price;
    const pos = (x) => Math.max(0, Math.min(1, (x - lo) / (hi - lo)));
    const bar = el('div', { class: 'rangebar', style: 'margin-top:6px' },
      el('div', { class: 'track', style: 'height:8px' },
        mean != null ? el('div', { class: 'mark', style: `left:calc(${(pos(mean) * 100).toFixed(1)}% - 1px);background:#a78bfa;height:14px;top:-3px` }) : null,
        cp != null ? el('div', { class: 'mark', style: `left:calc(${(pos(cp) * 100).toFixed(1)}% - 1px);height:14px;top:-3px` }) : null,
      ),
      el('div', { class: 'lbls' }, el('span', { text: 'Low ' + fmtPrice(lo, cur) }), el('span', { text: 'High ' + fmtPrice(hi, cur) })),
    );
    card.appendChild(el('div', {}, el('div', { class: 'small muted', text: '12-month price targets — blue = current price, purple = mean target' }), bar,
      el('div', { class: 'pillrow' }, mean != null ? pill('Mean target', fmtPrice(mean, cur)) : null, cp != null && mean != null ? pill('Implied vs. price', fmtPct((mean - cp) / cp)) : null,
        d.metrics?.find((m) => m.label === 'Analysts covering') ? pill('Analysts', fmtInt(d.metrics.find((m) => m.label === 'Analysts covering').value)) : null,
        d.analyst?.recommendationKey ? pill('Consensus key', String(d.analyst.recommendationKey).replace(/_/g, ' ')) : null)));
  }
  const tr = a.recommendationTrend || [];
  if (tr.length) {
    card.appendChild(el('h3', { text: 'Recommendation distribution', style: 'margin-top:14px' }));
    card.appendChild(chartBox('chart-recs'));
    card._drawRecs = () => {
      const cv = $('#chart-recs'); if (!cv || !chartReady()) return;
      const labels = tr.map((t) => ({ '0m': 'Now', '-1m': '1mo ago', '-2m': '2mo ago', '-3m': '3mo ago' }[t.period] || t.period));
      const stack = (label, key, color) => ({ label, data: tr.map((t) => t[key] || 0), backgroundColor: color, stack: 's' });
      const datasets = [
        stack('Strong buy', 'strongBuy', '#15803d'),
        stack('Buy', 'buy', '#34d399'),
        stack('Hold', 'hold', '#fbbf24'),
        stack('Sell', 'sell', '#fb7185'),
        stack('Strong sell', 'strongSell', '#b91c1c'),
      ];
      const options = {
        plugins: { tooltip: { mode: 'index' } },
        scales: {
          x: { stacked: true, grid: { display: false } },
          y: { stacked: true, ticks: { precision: 0 }, grid: { color: 'rgba(36,48,68,.4)' } },
        },
      };
      newChart(cv, { type: 'bar', data: { labels, datasets }, options });
    };
  }
  if (!tr.length && lo == null) card.appendChild(noData('No analyst data available for this company.'));
  return card;
}

/* ---- about ---- */
function buildAboutCard(d, cur) {
  const card = el('div', { class: 'card' });
  card.appendChild(el('h2', { text: 'About the company' }));
  const p = d.profile || {};
  const kv = el('dl', { class: 'kv' });
  const addKV = (k, v) => { if (v == null || v === '') return; kv.appendChild(el('dt', { text: k })); kv.appendChild(v instanceof Node ? el('dd', {}, v) : el('dd', { text: String(v) })); };
  addKV('Ticker', d.symbol);
  addKV('Exchange', p.exchangeName);
  addKV('Sector', p.sector);
  addKV('Industry', p.industry);
  addKV('Employees', p.employees != null ? fmtInt(p.employees) : null);
  addKV('Reporting currency', d.financialCurrency || cur || null);
  if (p.website) addKV('Website', el('a', { href: p.website, target: '_blank', rel: 'noopener', text: p.website }));
  const loc = [p.address, p.city, p.state, p.country].filter(Boolean).join(', ');
  addKV('Headquarters', loc || null);
  addKV('Phone', p.phone);
  card.appendChild(kv);
  if (p.summary) card.appendChild(el('p', { class: 'summary', style: 'margin-top:12px', text: p.summary }));
  if (p.officers && p.officers.length) {
    card.appendChild(el('h3', { text: 'Key people', style: 'margin-top:14px' }));
    const ow = el('div', { class: 'officers' });
    p.officers.slice(0, 8).forEach((o) => ow.appendChild(el('div', {}, el('b', { text: o.name }), o.title ? ' — ' + o.title : '', o.pay ? '  ·  pay ' + fmtMoney(o.pay, cur) : '')));
    card.appendChild(ow);
  }
  card.appendChild(el('p', { class: 'small muted', style: 'margin-top:14px', text: 'Company facts via Yahoo Finance / Tel Aviv Stock Exchange. Figures are delayed and may contain reporting gaps — always cross-check with official filings (TASE MAYA / ISA Magna) before investing.' }));
  return card;
}

/* ---- shared chart helpers ---- */
function mkBar(label, data, color) { return { type: 'bar', label, data, backgroundColor: color + 'cc', borderColor: color, borderWidth: 1, borderRadius: 3 }; }
function barOpts(cur) {
  return {
    interaction: { mode: 'index', intersect: false },
    plugins: { tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${c.parsed.y == null ? '—' : fmtMoney(c.parsed.y, cur)}` } } },
    scales: { x: { grid: { display: false } }, y: { ticks: { callback: (v) => fmtMoney(v, cur) }, grid: { color: 'rgba(36,48,68,.4)' } } },
  };
}
function renderAllCharts(d, cur) {
  if (!chartReady()) { toast('Charts library failed to load — showing data tables only.'); return; }
  // walk all chart-cards and call their _draw / _drawRecs
  $$('.chart-card', $('#report')).forEach((card) => { try { card._draw && card._draw(); card._drawRecs && card._drawRecs(); } catch (e) { console.error(e); } });
  // analyst card may live in a normal .card
  $$('.card', $('#report')).forEach((card) => { try { card._drawRecs && card._drawRecs(); } catch (e) { console.error(e); } });
}

/* ============================ boot ============================ */
loadDirectory().then(() => route());
