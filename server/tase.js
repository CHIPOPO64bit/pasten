// OPTIONAL integration with the TASE Data Hub (https://datawise.tase.co.il/).
//
// The Data Hub is the Tel Aviv Stock Exchange's official open-data API. It is
// free but requires registration to obtain an API key/secret (OAuth2 client
// credentials). When TASE_API_KEY / TASE_API_SECRET are present in the
// environment, we use it to pull the authoritative list of TASE-listed
// securities so the company directory covers (almost) every Israeli public
// company instead of just the built-in curated list.
//
// This module is intentionally defensive: any failure simply means we fall back
// to the curated directory + Yahoo Finance data, so the app always works.

const TOKEN_URL = 'https://openapigw.tase.co.il/tase/prod/oauth/oauth2/token';
const API_BASE = 'https://openapigw.tase.co.il/tase/prod/api/v1';

const ENABLED = !!(process.env.TASE_API_KEY && process.env.TASE_API_SECRET);

let token = { value: null, exp: 0 };

async function getToken() {
  if (token.value && Date.now() < token.exp - 30_000) return token.value;
  const basic = Buffer.from(
    `${process.env.TASE_API_KEY}:${process.env.TASE_API_SECRET}`,
  ).toString('base64');
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials&scope=tase',
  });
  if (!r.ok) throw new Error(`TASE token ${r.status}`);
  const j = await r.json();
  token = {
    value: j.access_token,
    exp: Date.now() + (j.expires_in ? j.expires_in * 1000 : 3600_000),
  };
  return token.value;
}

async function apiGet(path) {
  const t = await getToken();
  const r = await fetch(API_BASE + path, {
    headers: { Authorization: `Bearer ${t}`, Accept: 'application/json', 'accept-language': 'en-US' },
  });
  if (!r.ok) throw new Error(`TASE ${r.status} ${path}`);
  return r.json();
}

// Returns [{ symbol, name, hebrew, sector, exchange, taseId }] or [] on any problem.
let listCache = { val: null, exp: 0 };
export async function getTaseSecurities() {
  if (!ENABLED) return [];
  if (listCache.val && Date.now() < listCache.exp) return listCache.val;
  const candidates = [
    '/basic-securities/trade-securities-list',
    '/basic-securities/companies-list',
    '/basic-securities/securities-types',
  ];
  for (const path of candidates) {
    try {
      const data = await apiGet(path);
      const rows = extractRows(data);
      if (rows.length) {
        const out = rows.map(normalizeRow).filter(Boolean);
        if (out.length) {
          listCache = { val: out, exp: Date.now() + 12 * 3600_000 };
          return out;
        }
      }
    } catch {
      /* try next candidate */
    }
  }
  return [];
}

function extractRows(data) {
  if (Array.isArray(data)) return data;
  if (!data || typeof data !== 'object') return [];
  // Data Hub responses tend to look like { result: { <key>: [...] } } or { <key>: [...] }
  for (const v of Object.values(data)) {
    if (Array.isArray(v)) return v;
    if (v && typeof v === 'object') {
      for (const vv of Object.values(v)) if (Array.isArray(vv)) return vv;
    }
  }
  return [];
}

function pick(row, keys) {
  for (const k of keys) {
    for (const rk of Object.keys(row)) {
      if (rk.toLowerCase() === k) return row[rk];
    }
  }
  return undefined;
}

function normalizeRow(row) {
  if (!row || typeof row !== 'object') return null;
  const symbolRaw = pick(row, ['symbol', 'tickersymbol', 'securitysymbol', 'symbolenglish']);
  const id = pick(row, ['securityid', 'companyid', 'id', 'securitynumber']);
  const nameEn = pick(row, ['securityname', 'companyname', 'name', 'securitynameenglish', 'longname', 'corporatename']);
  const nameHe = pick(row, ['securitynamehebrew', 'companynamehebrew', 'namehebrew', 'hebrewname']);
  const sector = pick(row, ['sectorname', 'subsectorname', 'sector', 'branchname', 'industryname', 'maincategory']);
  const sym = symbolRaw ? String(symbolRaw).trim().toUpperCase() : null;
  const name = nameEn ? String(nameEn).trim() : null;
  if (!sym && !id) return null;
  if (!name && !nameHe) return null;
  return {
    symbol: sym ? `${sym}.TA` : null,
    taseId: id != null ? String(id) : null,
    name: name || String(nameHe).trim(),
    hebrew: nameHe ? String(nameHe).trim() : undefined,
    sector: sector ? String(sector).trim() : 'Other (TASE)',
    exchange: 'TASE',
    source: 'tase-data-hub',
  };
}

export const taseEnabled = ENABLED;
