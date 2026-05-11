import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { getTaseSecurities, taseEnabled } from './tase.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(__dirname, '..', 'data', 'companies.json'), 'utf8'));

const CURATED = raw.companies.map((c) => ({ ...c, source: 'curated' }));
const CURATED_SECTORS = raw.sectors;

let merged = null;
let mergedAt = 0;
const MERGE_TTL = 12 * 3600_000;

export async function getAllCompanies() {
  if (merged && Date.now() - mergedAt < MERGE_TTL) return merged;
  let extra = [];
  if (taseEnabled) {
    try {
      extra = await getTaseSecurities();
    } catch {
      extra = [];
    }
  }
  const bySymbol = new Map();
  for (const c of CURATED) bySymbol.set(c.symbol.toUpperCase(), c);
  for (const c of extra) {
    if (!c.symbol) continue;
    const key = c.symbol.toUpperCase();
    if (!bySymbol.has(key)) bySymbol.set(key, c);
  }
  merged = [...bySymbol.values()].sort((a, b) => a.name.localeCompare(b.name));
  mergedAt = Date.now();
  return merged;
}

export async function listSectors() {
  const all = await getAllCompanies();
  const counts = new Map();
  for (const c of all) counts.set(c.sector, (counts.get(c.sector) || 0) + 1);
  // curated sectors first (stable order), then any extras alphabetically
  const ordered = [];
  for (const s of CURATED_SECTORS) if (counts.has(s)) ordered.push({ sector: s, count: counts.get(s) });
  for (const [s, n] of [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (!CURATED_SECTORS.includes(s)) ordered.push({ sector: s, count: n });
  }
  return { total: all.length, taseHubEnabled: taseEnabled, sectors: ordered };
}

export async function queryCompanies({ q, sector, limit = 500 } = {}) {
  const all = await getAllCompanies();
  let out = all;
  if (sector) out = out.filter((c) => c.sector === sector);
  if (q) {
    const needle = q.trim().toLowerCase();
    out = out.filter(
      (c) =>
        c.symbol.toLowerCase().includes(needle) ||
        c.name.toLowerCase().includes(needle) ||
        (c.hebrew && c.hebrew.includes(q.trim())),
    );
  }
  return out.slice(0, limit);
}

export async function findCompany(symbol) {
  const all = await getAllCompanies();
  const key = symbol.toUpperCase();
  return all.find((c) => c.symbol.toUpperCase() === key) || null;
}
