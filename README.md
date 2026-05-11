# Pasten — Israeli companies financial explorer

A search bar + visual financial report for Israeli public companies. Type a
company name or ticker (or browse by sector — energy, tech, banks, real
estate, …) and get a data-rich, chart-heavy snapshot of its financial state.

**It reports objective findings only.** Nothing here is scored, ranked, or
recommended — the goal is to put as much hard data in front of you as possible
so *you* can decide whether to invest.

## What you get per company

- **Live(ish) quote** — price, day change, market cap, 52-week range bar, day range.
- **Snapshot grid** — ~70 objective metrics grouped into Valuation, Profitability
  & margins, Growth, Income (TTM), Balance sheet & liquidity, Cash flow, Dividends,
  Market & trading, Shares & ownership, Analyst coverage, Key dates. Tap any metric
  for a plain-English definition.
- **Charts**
  - Share price (1M / 6M / YTD / 1Y / 5Y / Max).
  - Revenue & profit by fiscal year (revenue, gross profit, operating income, net income).
  - Profit margins over time (gross / operating / net %).
  - Cash flow by fiscal year (operating / investing / financing + free cash flow).
  - Balance sheet by fiscal year (assets vs. liabilities vs. equity; cash vs. debt).
  - EPS — actual vs. analyst estimate per quarter.
- **Full financial statements** — income statement, balance sheet, cash-flow
  statement, annual & quarterly, up to 6 periods, in scrollable tables.
- **Analyst consensus** — price-target range, recommendation distribution (shown
  as raw third-party data, not as advice).
- **Company profile** — sector, industry, employees, HQ, website, key people,
  business summary.

Built mobile-first, so it renders nicely on a phone.

## Data sources

- **Yahoo Finance** (free, no key) — quotes, fundamentals, financial statements,
  price history. Covers Tel Aviv Stock Exchange tickers (`.TA` suffix, e.g.
  `POLI.TA` = Bank Hapoalim) and Israeli companies dual-listed in the US
  (`TEVA`, `NICE`, `CYBR`, `ICL`, `ESLT`, …). Data is delayed.
- **TASE Data Hub** (`datawise.tase.co.il`, *optional*, free registration) — the
  Tel Aviv Stock Exchange's official open-data API. When configured, the company
  directory expands to (almost) every TASE-listed company instead of just the
  built-in curated list. See `.env.example`.

The built-in directory (`data/companies.json`) is a hand-curated list of major
Israeli & Israeli-dual-listed companies organised by sector. You can also search
**any** ticker directly — it doesn't have to be in the directory.

## Run it

Requires Node.js 18+ (Node 20+ recommended).

```bash
npm install
npm start
# open http://localhost:3000  (also reachable from your phone on the same
# network at http://<your-computer-ip>:3000)
```

Optional, to expand the directory with the full TASE securities list:

```bash
cp .env.example .env
# put your TASE Data Hub key/secret in .env, then:
npm start
```

## Notes & caveats

- Needs an internet connection — it proxies Yahoo Finance.
- Yahoo occasionally has gaps: banks, insurers and limited partnerships often
  don't expose a standard income statement / cash-flow statement, so some charts
  will say "not reported". The app degrades gracefully.
- Tel Aviv prices on Yahoo are sometimes quoted in agorot (`ILA`, 1 ILS = 100
  agorot); the currency code is shown as-is so you know which unit you're looking at.
- **Informational use only.** Cross-check anything important against official
  filings (TASE MAYA / ISA Magna) before making investment decisions.

## Project layout

```
server/
  index.js       Express app: API + static hosting
  yahoo.js       Yahoo Finance client (cookie/crumb handling, caching)
  tase.js        Optional TASE Data Hub client
  companies.js   Loads/merges/filters the company directory
  report.js      Normalises Yahoo data into the report shape the UI consumes
data/
  companies.json Curated Israeli companies directory (by sector)
public/
  index.html, styles.css, app.js   Mobile-first single-page frontend
```
