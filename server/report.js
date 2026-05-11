// Turns Yahoo's quoteSummary blob into a clean, frontend-friendly report.
// Philosophy: surface objective findings only — no scoring, no buy/sell call.

function num(v) {
  if (v == null) return null;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'object') {
    if ('raw' in v) return num(v.raw);
    return null;
  }
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function epochToISO(v) {
  const n = num(v);
  if (n == null) return null;
  const ms = n > 1e12 ? n : n * 1000;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

function pct(v) {
  // Yahoo gives margins/yields as fractions (0.1234) — keep as fraction, frontend formats.
  return num(v);
}

const IS_FIELDS = {
  totalRevenue: 'Total revenue',
  costOfRevenue: 'Cost of revenue',
  grossProfit: 'Gross profit',
  researchDevelopment: 'R&D expense',
  sellingGeneralAdministrative: 'SG&A expense',
  totalOperatingExpenses: 'Total operating expenses',
  operatingIncome: 'Operating income',
  ebit: 'EBIT',
  interestExpense: 'Interest expense',
  incomeBeforeTax: 'Pre-tax income',
  incomeTaxExpense: 'Income tax',
  netIncome: 'Net income',
  netIncomeApplicableToCommonShares: 'Net income to common',
};

const BS_FIELDS = {
  cash: 'Cash & equivalents',
  shortTermInvestments: 'Short-term investments',
  netReceivables: 'Net receivables',
  inventory: 'Inventory',
  otherCurrentAssets: 'Other current assets',
  totalCurrentAssets: 'Total current assets',
  longTermInvestments: 'Long-term investments',
  propertyPlantEquipment: 'Property, plant & equipment',
  goodWill: 'Goodwill',
  intangibleAssets: 'Intangible assets',
  otherAssets: 'Other assets',
  totalAssets: 'Total assets',
  accountsPayable: 'Accounts payable',
  shortLongTermDebt: 'Short-term / current debt',
  otherCurrentLiab: 'Other current liabilities',
  totalCurrentLiabilities: 'Total current liabilities',
  longTermDebt: 'Long-term debt',
  otherLiab: 'Other liabilities',
  totalLiab: 'Total liabilities',
  commonStock: 'Common stock',
  retainedEarnings: 'Retained earnings',
  treasuryStock: 'Treasury stock / other equity',
  totalStockholderEquity: 'Total shareholders equity',
  netTangibleAssets: 'Net tangible assets',
};

const CF_FIELDS = {
  netIncome: 'Net income',
  depreciation: 'Depreciation & amortization',
  changeToNetincome: 'Adjustments to net income',
  changeToAccountReceivables: 'Change in receivables',
  changeToInventory: 'Change in inventory',
  changeToLiabilities: 'Change in payables',
  changeToOperatingActivities: 'Other operating activities',
  totalCashFromOperatingActivities: 'Cash from operating activities',
  capitalExpenditures: 'Capital expenditures',
  investments: 'Investments (net)',
  otherCashflowsFromInvestingActivities: 'Other investing activities',
  totalCashflowsFromInvestingActivities: 'Cash from investing activities',
  dividendsPaid: 'Dividends paid',
  netBorrowings: 'Net borrowings',
  repurchaseOfStock: 'Stock repurchased',
  issuanceOfStock: 'Stock issued',
  otherCashflowsFromFinancingActivities: 'Other financing activities',
  totalCashFromFinancingActivities: 'Cash from financing activities',
  effectOfExchangeRate: 'FX effect on cash',
  changeInCash: 'Net change in cash',
};

function mapStatements(arr, dateKey, fieldMap) {
  if (!Array.isArray(arr)) return [];
  return arr
    .map((row) => {
      const date = epochToISO(row?.[dateKey]);
      const fields = {};
      for (const k of Object.keys(fieldMap)) fields[k] = num(row?.[k]);
      return { date, fields };
    })
    .filter((r) => r.date)
    .sort((a, b) => (a.date < b.date ? -1 : 1));
}

export function buildReport({ symbol, requestedSymbol, directory, summary, chart1y, warnings = [] }) {
  const assetProfile = summary?.assetProfile || summary?.summaryProfile || {};
  const price = summary?.price || {};
  const sd = summary?.summaryDetail || {};
  const ks = summary?.defaultKeyStatistics || {};
  const fd = summary?.financialData || {};
  const earnings = summary?.earnings || {};
  const earningsHistory = summary?.earningsHistory || {};
  const earningsTrend = summary?.earningsTrend || {};
  const recTrend = summary?.recommendationTrend?.trend || [];
  const holders = summary?.majorHoldersBreakdown || {};

  const incomeAnnual = mapStatements(summary?.incomeStatementHistory?.incomeStatementHistory, 'endDate', IS_FIELDS);
  const incomeQ = mapStatements(summary?.incomeStatementHistoryQuarterly?.incomeStatementHistory, 'endDate', IS_FIELDS);
  const balanceAnnual = mapStatements(summary?.balanceSheetHistory?.balanceSheetStatements, 'endDate', BS_FIELDS);
  const balanceQ = mapStatements(summary?.balanceSheetHistoryQuarterly?.balanceSheetStatements, 'endDate', BS_FIELDS);
  const cashAnnual = mapStatements(summary?.cashflowStatementHistory?.cashflowStatements, 'endDate', CF_FIELDS);
  const cashQ = mapStatements(summary?.cashflowStatementHistoryQuarterly?.cashflowStatements, 'endDate', CF_FIELDS);

  // ---- derived time series ----
  const revenueSeries = incomeAnnual.map((r) => ({
    period: r.date.slice(0, 4),
    revenue: r.fields.totalRevenue,
    grossProfit: r.fields.grossProfit,
    operatingIncome: r.fields.operatingIncome,
    netIncome: r.fields.netIncome,
  }));
  const marginsSeries = incomeAnnual.map((r) => {
    const rev = r.fields.totalRevenue;
    const m = (x) => (rev && x != null && rev !== 0 ? x / rev : null);
    return {
      period: r.date.slice(0, 4),
      gross: m(r.fields.grossProfit),
      operating: m(r.fields.operatingIncome ?? r.fields.ebit),
      net: m(r.fields.netIncome),
    };
  });
  const cashflowSeries = cashAnnual.map((r) => {
    const op = r.fields.totalCashFromOperatingActivities;
    const capex = r.fields.capitalExpenditures;
    return {
      period: r.date.slice(0, 4),
      operating: op,
      investing: r.fields.totalCashflowsFromInvestingActivities,
      financing: r.fields.totalCashFromFinancingActivities,
      capex,
      freeCashFlow: op != null && capex != null ? op + capex : null, // capex is negative in Yahoo data
    };
  });
  const balanceSeries = balanceAnnual.map((r) => {
    const debt =
      (r.fields.shortLongTermDebt || 0) + (r.fields.longTermDebt || 0) || null;
    return {
      period: r.date.slice(0, 4),
      totalAssets: r.fields.totalAssets,
      totalLiabilities: r.fields.totalLiab,
      totalEquity: r.fields.totalStockholderEquity,
      cash: r.fields.cash,
      totalDebt: debt,
      currentAssets: r.fields.totalCurrentAssets,
      currentLiabilities: r.fields.totalCurrentLiabilities,
    };
  });

  // EPS series: prefer earningsHistory (quarterly actual vs estimate)
  const epsSeries = (earningsHistory?.history || [])
    .map((h) => ({
      period: h.quarter ? epochToISO(h.quarter) : null,
      actual: num(h.epsActual),
      estimate: num(h.epsEstimate),
      surprisePercent: num(h.surprisePercent),
    }))
    .filter((x) => x.period);

  const earningsYearly = (earnings?.financialsChart?.yearly || []).map((y) => ({
    period: String(y.date),
    revenue: num(y.revenue),
    earnings: num(y.earnings),
  }));
  const earningsQuarterly = (earnings?.financialsChart?.quarterly || []).map((y) => ({
    period: String(y.date),
    revenue: num(y.revenue),
    earnings: num(y.earnings),
  }));

  // ---- objective metric grid ----
  const M = [];
  const add = (group, label, value, format, help) => {
    if (value === null || value === undefined || (typeof value === 'number' && !Number.isFinite(value))) return;
    M.push({ group, label, value, format, help });
  };
  const curr = price.currency || sd.currency || fd.financialCurrency || '';

  // Valuation
  add('Valuation', 'Market capitalization', num(price.marketCap ?? sd.marketCap), { type: 'money', currency: curr },
    'Total market value of all outstanding shares = share price × shares outstanding.');
  add('Valuation', 'Enterprise value', num(ks.enterpriseValue), { type: 'money', currency: curr },
    'Market cap + total debt − cash. An approximation of the cost to acquire the whole business.');
  add('Valuation', 'Trailing P/E', num(sd.trailingPE), { type: 'ratio' },
    'Share price ÷ earnings per share over the last 12 months.');
  add('Valuation', 'Forward P/E', num(sd.forwardPE ?? ks.forwardPE), { type: 'ratio' },
    'Share price ÷ analysts’ estimated earnings per share for the next 12 months.');
  add('Valuation', 'PEG ratio', num(ks.pegRatio), { type: 'ratio' },
    'P/E ratio divided by expected earnings growth rate. A way to view P/E relative to growth.');
  add('Valuation', 'Price / sales (TTM)', num(sd.priceToSalesTrailing12Months), { type: 'ratio' },
    'Market cap ÷ revenue over the last 12 months.');
  add('Valuation', 'Price / book', num(ks.priceToBook), { type: 'ratio' },
    'Share price ÷ book value (shareholders equity) per share.');
  add('Valuation', 'EV / revenue', num(ks.enterpriseToRevenue), { type: 'ratio' },
    'Enterprise value ÷ revenue over the last 12 months.');
  add('Valuation', 'EV / EBITDA', num(ks.enterpriseToEbitda), { type: 'ratio' },
    'Enterprise value ÷ earnings before interest, taxes, depreciation and amortization.');
  add('Valuation', 'Book value / share', num(ks.bookValue), { type: 'money', currency: curr },
    'Shareholders equity divided by shares outstanding.');

  // Profitability
  add('Profitability & margins', 'Gross margin', pct(fd.grossMargins), { type: 'percent' },
    '(Revenue − cost of revenue) ÷ revenue.');
  add('Profitability & margins', 'Operating margin', pct(fd.operatingMargins), { type: 'percent' },
    'Operating income ÷ revenue.');
  add('Profitability & margins', 'EBITDA margin', pct(fd.ebitdaMargins), { type: 'percent' },
    'EBITDA ÷ revenue.');
  add('Profitability & margins', 'Profit (net) margin', pct(fd.profitMargins ?? ks.profitMargins), { type: 'percent' },
    'Net income ÷ revenue.');
  add('Profitability & margins', 'Return on equity', pct(fd.returnOnEquity), { type: 'percent' },
    'Net income ÷ shareholders equity.');
  add('Profitability & margins', 'Return on assets', pct(fd.returnOnAssets), { type: 'percent' },
    'Net income ÷ total assets.');
  add('Profitability & margins', 'EBITDA', num(fd.ebitda), { type: 'money', currency: curr },
    'Earnings before interest, taxes, depreciation and amortization (last 12 months).');
  add('Profitability & margins', 'Gross profit (TTM)', num(fd.grossProfits), { type: 'money', currency: curr },
    'Revenue minus cost of revenue over the last 12 months.');

  // Growth
  add('Growth', 'Revenue growth (YoY)', pct(fd.revenueGrowth), { type: 'percent' },
    'Most recent quarter revenue vs. the same quarter a year earlier.');
  add('Growth', 'Earnings growth (YoY)', pct(fd.earningsGrowth), { type: 'percent' },
    'Most recent quarter earnings vs. the same quarter a year earlier.');
  add('Growth', 'Quarterly earnings growth (YoY)', pct(ks.earningsQuarterlyGrowth), { type: 'percent' },
    'Year-over-year change in quarterly net income.');
  add('Growth', '52-week price change', pct(ks['52WeekChange']), { type: 'percent' },
    'Total share price return over the last 52 weeks.');

  // Income
  add('Income statement (TTM)', 'Total revenue', num(fd.totalRevenue), { type: 'money', currency: curr },
    'Revenue over the last 12 months.');
  add('Income statement (TTM)', 'Revenue per share', num(fd.revenuePerShare), { type: 'money', currency: curr },
    'Revenue over the last 12 months divided by shares outstanding.');
  add('Income statement (TTM)', 'Net income to common', num(ks.netIncomeToCommon), { type: 'money', currency: curr },
    'Net income attributable to common shareholders over the last 12 months.');
  add('Income statement (TTM)', 'Trailing EPS', num(ks.trailingEps), { type: 'money', currency: curr },
    'Diluted earnings per share over the last 12 months.');
  add('Income statement (TTM)', 'Forward EPS', num(ks.forwardEps), { type: 'money', currency: curr },
    'Analysts’ estimated earnings per share for the next 12 months.');

  // Balance sheet & liquidity
  add('Balance sheet & liquidity', 'Total cash', num(fd.totalCash), { type: 'money', currency: curr },
    'Cash and short-term investments on the most recent balance sheet.');
  add('Balance sheet & liquidity', 'Total cash per share', num(fd.totalCashPerShare), { type: 'money', currency: curr },
    'Total cash divided by shares outstanding.');
  add('Balance sheet & liquidity', 'Total debt', num(fd.totalDebt), { type: 'money', currency: curr },
    'Short-term plus long-term debt on the most recent balance sheet.');
  add('Balance sheet & liquidity', 'Debt / equity', num(fd.debtToEquity) != null ? num(fd.debtToEquity) / 100 : null, { type: 'percent' },
    'Total debt divided by shareholders equity (shown as a percentage).');
  add('Balance sheet & liquidity', 'Current ratio', num(fd.currentRatio), { type: 'ratio' },
    'Current assets ÷ current liabilities. Above 1 means current assets cover current liabilities.');
  add('Balance sheet & liquidity', 'Quick ratio', num(fd.quickRatio), { type: 'ratio' },
    'Current assets excluding inventory ÷ current liabilities.');

  // Cash flow
  add('Cash flow (TTM)', 'Operating cash flow', num(fd.operatingCashflow), { type: 'money', currency: curr },
    'Cash generated by core operations over the last 12 months.');
  add('Cash flow (TTM)', 'Free cash flow', num(fd.freeCashflow), { type: 'money', currency: curr },
    'Operating cash flow minus capital expenditures over the last 12 months.');

  // Dividends
  add('Dividends', 'Dividend rate (annual)', num(sd.dividendRate), { type: 'money', currency: curr },
    'Expected annual dividend per share.');
  add('Dividends', 'Dividend yield', pct(sd.dividendYield), { type: 'percent' },
    'Annual dividend per share ÷ share price.');
  add('Dividends', '5-year average dividend yield', num(sd.fiveYearAvgDividendYield) != null ? num(sd.fiveYearAvgDividendYield) / 100 : null, { type: 'percent' },
    'Average dividend yield over the past five years.');
  add('Dividends', 'Payout ratio', pct(sd.payoutRatio), { type: 'percent' },
    'Share of earnings paid out as dividends.');
  add('Dividends', 'Ex-dividend date', epochToISO(sd.exDividendDate), { type: 'date' },
    'On/after this date a buyer is not entitled to the next dividend.');
  add('Dividends', 'Last dividend value', num(ks.lastDividendValue), { type: 'money', currency: curr },
    'Amount of the most recent dividend per share.');

  // Market / trading
  add('Market & trading', 'Previous close', num(sd.previousClose ?? price.regularMarketPreviousClose), { type: 'money', currency: curr }, 'Closing price of the previous trading session.');
  add('Market & trading', 'Open', num(sd.open ?? price.regularMarketOpen), { type: 'money', currency: curr }, 'Opening price of the current/most recent session.');
  add('Market & trading', 'Day range low', num(sd.dayLow ?? price.regularMarketDayLow), { type: 'money', currency: curr }, 'Lowest traded price in the session.');
  add('Market & trading', 'Day range high', num(sd.dayHigh ?? price.regularMarketDayHigh), { type: 'money', currency: curr }, 'Highest traded price in the session.');
  add('Market & trading', '52-week low', num(sd.fiftyTwoWeekLow), { type: 'money', currency: curr }, 'Lowest closing price over the past 52 weeks.');
  add('Market & trading', '52-week high', num(sd.fiftyTwoWeekHigh), { type: 'money', currency: curr }, 'Highest closing price over the past 52 weeks.');
  add('Market & trading', '50-day average', num(sd.fiftyDayAverage), { type: 'money', currency: curr }, 'Average closing price over the last 50 trading days.');
  add('Market & trading', '200-day average', num(sd.twoHundredDayAverage), { type: 'money', currency: curr }, 'Average closing price over the last 200 trading days.');
  add('Market & trading', 'Beta (5Y monthly)', num(sd.beta ?? ks.beta), { type: 'ratio' }, 'Sensitivity of the share price to overall market moves. 1 ≈ moves with the market.');
  add('Market & trading', 'Volume', num(sd.volume ?? price.regularMarketVolume), { type: 'int' }, 'Shares traded in the current/most recent session.');
  add('Market & trading', 'Average volume', num(sd.averageVolume), { type: 'int' }, 'Average daily trading volume.');

  // Share structure & ownership
  add('Shares & ownership', 'Shares outstanding', num(ks.sharesOutstanding), { type: 'int' }, 'Total number of shares issued and held by all shareholders.');
  add('Shares & ownership', 'Float shares', num(ks.floatShares), { type: 'int' }, 'Shares available for public trading (excludes closely-held shares).');
  add('Shares & ownership', 'Implied shares outstanding', num(ks.impliedSharesOutstanding), { type: 'int' }, 'Shares outstanding including all share classes.');
  add('Shares & ownership', 'Held by insiders', pct(holders.insidersPercentHeld), { type: 'percent' }, 'Percentage of shares held by company insiders.');
  add('Shares & ownership', 'Held by institutions', pct(holders.institutionsPercentHeld), { type: 'percent' }, 'Percentage of shares held by institutional investors.');
  add('Shares & ownership', 'Short shares', num(ks.sharesShort), { type: 'int' }, 'Number of shares sold short as of the last reported date.');
  add('Shares & ownership', 'Short ratio', num(ks.shortRatio), { type: 'ratio' }, 'Shares short divided by average daily volume (days-to-cover).');
  add('Shares & ownership', 'Short % of float', pct(ks.shortPercentOfFloat), { type: 'percent' }, 'Shares short as a percentage of the float.');

  // Analyst coverage (objective tallies, not advice)
  add('Analyst coverage', 'Analysts covering', num(fd.numberOfAnalystOpinions), { type: 'int' }, 'Number of analysts contributing price targets/estimates.');
  add('Analyst coverage', 'Mean price target', num(fd.targetMeanPrice), { type: 'money', currency: curr }, 'Average of analyst 12-month price targets.');
  add('Analyst coverage', 'Low price target', num(fd.targetLowPrice), { type: 'money', currency: curr }, 'Lowest analyst 12-month price target.');
  add('Analyst coverage', 'High price target', num(fd.targetHighPrice), { type: 'money', currency: curr }, 'Highest analyst 12-month price target.');
  add('Analyst coverage', 'Consensus rating (1=buy … 5=sell)', num(fd.recommendationMean), { type: 'ratio' }, 'Average of analyst recommendations on a 1-to-5 scale (this is the raw consensus, not our opinion).');

  // Calendar
  const ce = summary?.calendarEvents || {};
  const earningsDates = ce?.earnings?.earningsDate || [];
  add('Key dates', 'Next earnings date', earningsDates.length ? epochToISO(earningsDates[0]) : null, { type: 'date' }, 'Estimated date of the next earnings release.');
  add('Key dates', 'Most recent quarter', epochToISO(ks.mostRecentQuarter), { type: 'date' }, 'End date of the most recent reported fiscal quarter.');
  add('Key dates', 'Last fiscal year end', epochToISO(ks.lastFiscalYearEnd), { type: 'date' }, 'End date of the last reported fiscal year.');

  const officers = (assetProfile.companyOfficers || [])
    .map((o) => ({ name: o.name, title: o.title, age: o.age, pay: num(o.totalPay) }))
    .filter((o) => o.name);

  const recommendationTrend = recTrend.map((r) => ({
    period: r.period,
    strongBuy: r.strongBuy,
    buy: r.buy,
    hold: r.hold,
    sell: r.sell,
    strongSell: r.strongSell,
  }));

  return {
    symbol,
    requestedSymbol,
    asOf: new Date().toISOString(),
    currency: curr,
    financialCurrency: fd.financialCurrency || null,
    directory: directory || null,
    profile: {
      longName: price.longName || assetProfile.longName || directory?.name || symbol,
      shortName: price.shortName || directory?.name || symbol,
      hebrewName: directory?.hebrew || null,
      sector: assetProfile.sector || directory?.sector || null,
      industry: assetProfile.industry || null,
      employees: num(assetProfile.fullTimeEmployees),
      website: assetProfile.website || null,
      country: assetProfile.country || null,
      city: assetProfile.city || null,
      state: assetProfile.state || null,
      address: [assetProfile.address1, assetProfile.address2].filter(Boolean).join(', ') || null,
      phone: assetProfile.phone || null,
      summary: assetProfile.longBusinessSummary || null,
      exchangeName: price.exchangeName || directory?.exchange || null,
      quoteType: price.quoteType || null,
      officers,
    },
    quote: {
      price: num(price.regularMarketPrice ?? fd.currentPrice),
      previousClose: num(price.regularMarketPreviousClose ?? sd.previousClose),
      open: num(price.regularMarketOpen ?? sd.open),
      dayHigh: num(price.regularMarketDayHigh ?? sd.dayHigh),
      dayLow: num(price.regularMarketDayLow ?? sd.dayLow),
      change: num(price.regularMarketChange),
      changePercent: num(price.regularMarketChangePercent),
      marketCap: num(price.marketCap ?? sd.marketCap),
      currency: curr,
      currencySymbol: price.currencySymbol || null,
      exchangeName: price.exchangeName || directory?.exchange || null,
      marketState: price.marketState || null,
      preMarketPrice: num(price.preMarketPrice),
      preMarketChangePercent: num(price.preMarketChangePercent),
      postMarketPrice: num(price.postMarketPrice),
      postMarketChangePercent: num(price.postMarketChangePercent),
      fiftyTwoWeekLow: num(sd.fiftyTwoWeekLow),
      fiftyTwoWeekHigh: num(sd.fiftyTwoWeekHigh),
    },
    metrics: M,
    statements: {
      income: { annual: incomeAnnual, quarterly: incomeQ, fieldLabels: IS_FIELDS },
      balance: { annual: balanceAnnual, quarterly: balanceQ, fieldLabels: BS_FIELDS },
      cashflow: { annual: cashAnnual, quarterly: cashQ, fieldLabels: CF_FIELDS },
    },
    series: {
      revenue: revenueSeries,
      margins: marginsSeries,
      cashflow: cashflowSeries,
      balance: balanceSeries,
      eps: epsSeries,
      earningsYearly,
      earningsQuarterly,
    },
    analyst: {
      recommendationTrend,
      recommendationKey: fd.recommendationKey || null,
      earningsTrend: (earningsTrend.trend || []).map((t) => ({
        period: t.period,
        endDate: t.endDate,
        growth: num(t.growth),
        revenueAvg: num(t.revenueEstimate?.avg),
        earningsAvg: num(t.earningsEstimate?.avg),
      })),
    },
    price1y: chart1y || null,
    warnings,
  };
}

export { num as _num };
