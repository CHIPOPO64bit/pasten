import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync } from 'node:fs';

import { getQuoteSummary, getChart, search as yahooSearch, authStatus } from './yahoo.js';
import { buildReport } from './report.js';
import { listSectors, queryCompanies, findCompany } from './companies.js';
import { taseEnabled } from './tase.js';

// load .env if present (no dependency needed)
try {
  const __d = dirname(fileURLToPath(import.meta.url));
  const envText = readFileSync(join(__d, '..', '.env'), 'utf8');
  for (const line of envText.split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch {
  /* no .env, fine */
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});

function isPlausibleSymbol(s) {
  return typeof s === 'string' && /^[A-Za-z0-9.\-^=]{1,20}$/.test(s);
}

const asyncH = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((e) => {
    res.status(502).json({ error: String(e?.message || e) });
  });

app.get('/api/health', (req, res) => {
  res.json({ ok: true, taseHubEnabled: taseEnabled, yahooAuth: authStatus() });
});

app.get('/api/sectors', asyncH(async (req, res) => {
  res.json(await listSectors());
}));

app.get('/api/companies', asyncH(async (req, res) => {
  const { q, sector } = req.query;
  const list = await queryCompanies({ q: typeof q === 'string' ? q : '', sector: typeof sector === 'string' ? sector : '' });
  res.json({ count: list.length, companies: list });
}));

app.get('/api/search', asyncH(async (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  if (!q) return res.json({ query: q, directory: [], external: [] });
  const directory = await queryCompanies({ q, limit: 30 });
  let external = [];
  if (q.length >= 2) {
    const seen = new Set(directory.map((c) => c.symbol.toUpperCase()));
    external = (await yahooSearch(q))
      .filter((r) => /EQUITY|ETF|INDEX|MUTUALFUND/i.test(r.type) || !r.type)
      .filter((r) => !seen.has(r.symbol.toUpperCase()))
      .slice(0, 10);
  }
  res.json({ query: q, directory, external });
}));

app.get('/api/company/:symbol', asyncH(async (req, res) => {
  const requested = req.params.symbol;
  if (!isPlausibleSymbol(requested)) return res.status(400).json({ error: 'Invalid symbol' });
  const symbol = requested.toUpperCase();
  const warnings = [];

  const directory = await findCompany(symbol);

  let summary = null;
  try {
    summary = await getQuoteSummary(symbol);
  } catch (e) {
    warnings.push(`Fundamentals unavailable: ${e.message}`);
  }

  let chart1y = null;
  try {
    chart1y = await getChart(symbol, '1y', '1d');
  } catch (e) {
    warnings.push(`Price history unavailable: ${e.message}`);
  }

  if (!summary && !chart1y) {
    return res.status(404).json({ error: `No data found for "${symbol}". Check the ticker (TASE tickers use the .TA suffix, e.g. POLI.TA).`, warnings });
  }

  // If summary is missing, still produce a minimal report from the chart meta.
  if (!summary) {
    const meta = chart1y?.meta || {};
    summary = {
      price: {
        regularMarketPrice: meta.regularMarketPrice,
        regularMarketPreviousClose: meta.chartPreviousClose ?? meta.previousClose,
        currency: meta.currency,
        exchangeName: meta.exchangeName || meta.fullExchangeName,
        shortName: meta.shortName,
        longName: meta.longName,
        quoteType: meta.instrumentType,
      },
      summaryDetail: {
        fiftyTwoWeekLow: meta.fiftyTwoWeekLow,
        fiftyTwoWeekHigh: meta.fiftyTwoWeekHigh,
        currency: meta.currency,
      },
    };
  }

  const report = buildReport({ symbol, requestedSymbol: requested, directory, summary, chart1y, warnings });
  res.json(report);
}));

app.get('/api/history/:symbol', asyncH(async (req, res) => {
  const symbol = req.params.symbol;
  if (!isPlausibleSymbol(symbol)) return res.status(400).json({ error: 'Invalid symbol' });
  const range = typeof req.query.range === 'string' ? req.query.range : '1y';
  const allowedRanges = ['1d', '5d', '1mo', '3mo', '6mo', '1y', '2y', '5y', '10y', 'ytd', 'max'];
  const r = allowedRanges.includes(range) ? range : '1y';
  const intervalMap = { '1d': '5m', '5d': '15m', '1mo': '1d', '3mo': '1d', '6mo': '1d', '1y': '1d', '2y': '1wk', '5y': '1wk', '10y': '1mo', ytd: '1d', max: '1mo' };
  const interval = typeof req.query.interval === 'string' ? req.query.interval : intervalMap[r] || '1d';
  const data = await getChart(symbol.toUpperCase(), r, interval);
  res.json(data);
}));

// ---- static frontend ----
app.use(express.static(join(__dirname, '..', 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  Pasten — Israeli companies financial explorer`);
  console.log(`  → http://localhost:${PORT}`);
  console.log(`  TASE Data Hub: ${taseEnabled ? 'enabled' : 'not configured (using curated directory + Yahoo Finance)'}\n`);
});
