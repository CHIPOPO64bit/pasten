// Minimal Yahoo Finance client.
// Public, key-less endpoints. quoteSummary now requires a "crumb" + cookie pair,
// which we fetch once and cache. Everything degrades gracefully if Yahoo changes
// things under us: callers get whatever data we managed to retrieve.

const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

const BASES = ['https://query1.finance.yahoo.com', 'https://query2.finance.yahoo.com'];

let auth = { cookie: null, crumb: null, ts: 0 };
const AUTH_TTL = 30 * 60 * 1000; // 30 min

// tiny in-memory response cache
const cache = new Map();
function cacheGet(key) {
  const e = cache.get(key);
  if (e && Date.now() < e.exp) return e.val;
  if (e) cache.delete(key);
  return null;
}
function cacheSet(key, val, ttlMs) {
  cache.set(key, { val, exp: Date.now() + ttlMs });
}

async function fetchWithTimeout(url, opts = {}, ms = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function ensureAuth(force = false) {
  if (!force && auth.crumb && Date.now() - auth.ts < AUTH_TTL) return auth;

  // 1) obtain a session cookie
  let cookie = null;
  for (const url of ['https://fc.yahoo.com/', 'https://finance.yahoo.com/']) {
    try {
      const r = await fetchWithTimeout(url, {
        headers: { 'User-Agent': UA, Accept: 'text/html' },
        redirect: 'manual',
      });
      const sc = typeof r.headers.getSetCookie === 'function' ? r.headers.getSetCookie() : [];
      const raw = sc.length ? sc : [r.headers.get('set-cookie')].filter(Boolean);
      if (raw.length) {
        cookie = raw.map((c) => c.split(';')[0]).join('; ');
        if (cookie) break;
      }
    } catch {
      /* try next */
    }
  }

  // 2) trade cookie for a crumb
  let crumb = null;
  if (cookie) {
    try {
      const r = await fetchWithTimeout('https://query1.finance.yahoo.com/v1/test/getcrumb', {
        headers: { 'User-Agent': UA, Cookie: cookie, Accept: 'text/plain' },
      });
      const txt = (await r.text()).trim();
      if (txt && txt.length < 64 && !txt.includes('<')) crumb = txt;
    } catch {
      /* ignore */
    }
  }

  auth = { cookie, crumb, ts: Date.now() };
  return auth;
}

async function yget(path, { needAuth = false, ttlMs = 5 * 60 * 1000, retry = true } = {}) {
  const ck = path + (needAuth ? '|auth' : '');
  const cached = cacheGet(ck);
  if (cached) return cached;

  const { cookie, crumb } = needAuth ? await ensureAuth() : auth;

  let lastErr = null;
  for (const base of BASES) {
    let url = base + path;
    if (needAuth && crumb) url += (url.includes('?') ? '&' : '?') + 'crumb=' + encodeURIComponent(crumb);
    try {
      const r = await fetchWithTimeout(url, {
        headers: {
          'User-Agent': UA,
          Accept: 'application/json',
          ...(needAuth && cookie ? { Cookie: cookie } : {}),
        },
      });
      if (r.status === 401 && needAuth && retry) {
        await ensureAuth(true);
        return yget(path, { needAuth, ttlMs, retry: false });
      }
      if (!r.ok) {
        lastErr = new Error(`Yahoo ${r.status} for ${path}`);
        continue;
      }
      const json = await r.json();
      cacheSet(ck, json, ttlMs);
      return json;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('Yahoo request failed: ' + path);
}

const SUMMARY_MODULES = [
  'assetProfile',
  'price',
  'summaryProfile',
  'summaryDetail',
  'defaultKeyStatistics',
  'financialData',
  'incomeStatementHistory',
  'incomeStatementHistoryQuarterly',
  'balanceSheetHistory',
  'balanceSheetHistoryQuarterly',
  'cashflowStatementHistory',
  'cashflowStatementHistoryQuarterly',
  'earnings',
  'earningsHistory',
  'earningsTrend',
  'calendarEvents',
  'recommendationTrend',
  'majorHoldersBreakdown',
  'fundOwnership',
  'institutionOwnership',
];

export async function getQuoteSummary(symbol) {
  const sym = encodeURIComponent(symbol);
  const path =
    `/v10/finance/quoteSummary/${sym}?modules=${SUMMARY_MODULES.join(',')}` +
    `&formatted=false&lang=en-US&region=US`;
  const json = await yget(path, { needAuth: true, ttlMs: 10 * 60 * 1000 });
  const res = json?.quoteSummary?.result?.[0];
  if (!res) {
    const err = json?.quoteSummary?.error?.description || 'No data';
    throw new Error(err);
  }
  return res;
}

export async function getChart(symbol, range = '1y', interval = '1d') {
  const sym = encodeURIComponent(symbol);
  const path =
    `/v8/finance/chart/${sym}?range=${encodeURIComponent(range)}` +
    `&interval=${encodeURIComponent(interval)}&includePrePost=false&events=div%2Csplit`;
  const json = await yget(path, { needAuth: true, ttlMs: 5 * 60 * 1000 });
  const res = json?.chart?.result?.[0];
  if (!res) {
    const err = json?.chart?.error?.description || 'No price data';
    throw new Error(err);
  }
  const ts = res.timestamp || [];
  const q = res.indicators?.quote?.[0] || {};
  const adj = res.indicators?.adjclose?.[0]?.adjclose || [];
  const points = ts
    .map((t, i) => ({
      t: t * 1000,
      open: q.open?.[i] ?? null,
      high: q.high?.[i] ?? null,
      low: q.low?.[i] ?? null,
      close: q.close?.[i] ?? null,
      adjclose: adj[i] ?? q.close?.[i] ?? null,
      volume: q.volume?.[i] ?? null,
    }))
    .filter((p) => p.close != null);
  return { meta: res.meta || {}, points };
}

export async function search(query) {
  const path =
    `/v1/finance/search?q=${encodeURIComponent(query)}` +
    `&quotesCount=12&newsCount=0&listsCount=0&enableFuzzyQuery=true&lang=en-US&region=US`;
  try {
    const json = await yget(path, { needAuth: true, ttlMs: 10 * 60 * 1000 });
    return (json?.quotes || [])
      .filter((q) => q.symbol)
      .map((q) => ({
        symbol: q.symbol,
        name: q.shortname || q.longname || q.symbol,
        exchange: q.exchDisp || q.exchange || '',
        type: q.quoteType || q.typeDisp || '',
      }));
  } catch {
    return [];
  }
}

export function authStatus() {
  return { hasCrumb: !!auth.crumb, hasCookie: !!auth.cookie, age: auth.ts ? Date.now() - auth.ts : null };
}
