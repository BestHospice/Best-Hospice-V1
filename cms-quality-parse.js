'use strict';
/**
 * Pure parsers for CMS hospice quality files and cells.
 *
 * LEAF MODULE: zero requires. Every function is total - it either returns a
 * value or throws QualityParseError. Nothing here guesses, rounds, imputes or
 * defaults, because a wrong guess in this file becomes a wrong quality claim on
 * a provider's screen.
 *
 * These shapes are not hypothetical. They are the five value shapes actually
 * present in reports/cms-archive/hospice/2026-08-19/provider.csv.gz
 * (453,492 rows) and cahps_provider.csv.gz (146,718 rows):
 *
 *   297,278  plain numeric                     e.g. "96.62"
 *   107,117  "Not Available"                   suppressed, NOT zero
 *    21,376  "Yes" / "No"                      descriptive measures only
 *     ~19k   thousands separators              e.g. "1,152", "17,677"
 *     1,352  "Not Available(12)"               a FOOTNOTE GLUED INTO THE SCORE
 *    13,338  "Not Applicable"                  CAHPS structural non-values
 *
 * plus multi-valued footnotes ("2,5", "1,5", "6,7") and two different
 * measurement-period formats - "01/01/2023 - 12/31/2024" in the provider file
 * and "10/01/2023-09/30/2025", with no spaces, in the CAHPS file.
 */

// Hand-rolled and quote-aware, mirroring scripts/import-cms-hospice-data.js.
// Nothing is coerced: a CCN like "A01500" or "031598" stays exactly the string
// CMS published. Quoting matters more here than in the facility files - the CAHPS
// file quotes its headers and embeds commas inside measure names, so a naive
// split() reads Measure NAMES as if they were measure CODES.
function parseCsv(text) {
  const out = []; let row = []; let cur = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); out.push(row); row = []; cur = ''; }
    else if (c !== '\r') cur += c;
  }
  if (cur !== '' || row.length) { row.push(cur); out.push(row); }
  const head = out.shift() || [];
  return { head, rows: out.filter((r) => r.some((v) => v !== '')).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? '']))) };
}

class QualityParseError extends Error {
  constructor(message) { super(message); this.name = 'QualityParseError'; }
}

// CMS's no-value sentinels. "-" is CMS's "no footnote"/"no value" dash and is
// NOT a negative number. These are compared case-sensitively against the exact
// strings CMS publishes; a novel sentinel must fail closed rather than be
// absorbed by a loose match.
const VALUE_SENTINELS = Object.freeze(['', '-', 'Not Available', 'Not Applicable', 'N/A']);

// A footnote code that CMS glued onto the end of the Score cell, e.g.
// "Not Available(12)". Accepted ONLY when what precedes the parenthesis is
// itself a sentinel, so a real value can never be silently truncated.
const GLUED_FOOTNOTE_RE = /^(.*?)\((\d+(?:,\d+)*)\)$/;

// Thousands-separated integers/decimals, in valid thousands positions only.
// "1,152" and "17,677" match; "1,2" does not and therefore fails closed instead
// of being read as 12.
const THOUSANDS_RE = /^-?\d{1,3}(?:,\d{3})+(?:\.\d+)?$/;
const PLAIN_NUMBER_RE = /^-?\d+(?:\.\d+)?$/;

const FOOTNOTE_CODE_RE = /^\d{1,3}$/;

// Both published forms in one expression: the separator may or may not be
// surrounded by whitespace.
const PERIOD_RE = /^(\d{2})\/(\d{2})\/(\d{4})\s*-\s*(\d{2})\/(\d{2})\/(\d{4})$/;

const text = (v) => String(v == null ? '' : v).trim();
const isSentinel = (s) => VALUE_SENTINELS.indexOf(s) !== -1;

function toNumber(s) {
  if (THOUSANDS_RE.test(s)) return Number(s.replace(/,/g, ''));
  if (PLAIN_NUMBER_RE.test(s)) return Number(s);
  return null;
}

/**
 * Parse a Score (or Star Rating) cell.
 *
 * Returns { valueRaw, valueNumeric, suppressed, footnoteCodes }.
 *   - valueRaw is the cell VERBATIM, untrimmed of meaning: a suppressed row still
 *     records exactly what CMS said.
 *   - valueNumeric is null whenever CMS published no usable number. It is never
 *     0, never the mean, never carried over from another release.
 *   - footnoteCodes carries any footnote CMS glued into this cell; the caller
 *     merges it with the Footnote column.
 *
 * Throws for any shape not documented above, including "Yes"/"No", so a CMS
 * redefinition of a surfaced measure fails the ingestion instead of quietly
 * producing a null.
 */
function parseScoreCell(raw, label) {
  const valueRaw = String(raw == null ? '' : raw);
  const s = text(valueRaw);
  const where = label ? ` for ${label}` : '';

  if (isSentinel(s)) return { valueRaw, valueNumeric: null, suppressed: true, footnoteCodes: [] };

  const glued = GLUED_FOOTNOTE_RE.exec(s);
  if (glued) {
    const head = glued[1].trim();
    if (!isSentinel(head)) {
      throw new QualityParseError(
        `unparseable score${where}: "${s}" has a trailing (n) but "${head}" is not a CMS no-value sentinel`);
    }
    // Suppressed, and CMS told us why in the Score cell itself.
    return {
      valueRaw,
      valueNumeric: null,
      suppressed: true,
      footnoteCodes: glued[2].split(',').map((c) => c.trim()).filter(Boolean)
    };
  }

  const n = toNumber(s);
  if (n === null || !Number.isFinite(n)) {
    throw new QualityParseError(
      `unparseable score${where}: "${s}" is neither a CMS no-value sentinel nor a number`);
  }
  return { valueRaw, valueNumeric: n, suppressed: false, footnoteCodes: [] };
}

/**
 * Parse the Footnote column. CMS publishes "-" or "" for none and comma-joined
 * codes such as "2,5" or "6,7" when several apply, so the result is always an
 * array and never an integer.
 */
function parseFootnoteCell(raw, label) {
  const s = text(raw);
  const where = label ? ` for ${label}` : '';
  if (s === '' || s === '-') return [];
  const codes = s.split(',').map((c) => c.trim()).filter((c) => c !== '');
  if (!codes.length) return [];
  for (const c of codes) {
    if (!FOOTNOTE_CODE_RE.test(c)) {
      throw new QualityParseError(`unparseable footnote${where}: "${s}" contains non-numeric code "${c}"`);
    }
  }
  return codes;
}

const isRealCalendarDate = (yyyy, mm, dd) => {
  const d = new Date(Date.UTC(yyyy, mm - 1, dd));
  return !Number.isNaN(d.getTime())
    && d.getUTCFullYear() === yyyy && d.getUTCMonth() === mm - 1 && d.getUTCDate() === dd;
};

/**
 * Parse a measurement period into PLAIN YYYY-MM-DD STRINGS, never JS Dates.
 *
 * A JS Date handed to a `::date` parameter is serialised by the pg driver in
 * LOCAL time, which truncates to the previous day at any negative UTC offset -
 * the exact silent off-by-one that corrupted every certification date in an
 * earlier phase before it was caught. Strings have no timezone to get wrong.
 *
 * Returns null when CMS published no period. Throws on a malformed one.
 */
function parsePeriodCell(raw, label) {
  const s = text(raw);
  const where = label ? ` for ${label}` : '';
  if (isSentinel(s)) return null;
  const m = PERIOD_RE.exec(s);
  if (!m) {
    throw new QualityParseError(
      `unparseable measurement period${where}: "${s}" is not MM/DD/YYYY - MM/DD/YYYY`);
  }
  const [, m1, d1, y1, m2, d2, y2] = m.map(Number);
  if (!isRealCalendarDate(y1, m1, d1) || !isRealCalendarDate(y2, m2, d2)) {
    throw new QualityParseError(`unparseable measurement period${where}: "${s}" contains a date that does not exist`);
  }
  const iso = (y, mo, d) => `${String(y).padStart(4, '0')}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
  const start = iso(y1, m1, d1);
  const end = iso(y2, m2, d2);
  if (start > end) {
    throw new QualityParseError(`unparseable measurement period${where}: "${s}" ends before it starts`);
  }
  return { start, end };
}

/**
 * CAHPS publishes its summary rating in a separate Star Rating column. Only a
 * whole 1-5 is accepted; anything else is either a sentinel (null) or drift.
 */
function parseStarRatingCell(raw, label) {
  const s = text(raw);
  const where = label ? ` for ${label}` : '';
  if (isSentinel(s)) return null;
  if (!/^[1-5]$/.test(s)) {
    throw new QualityParseError(`unparseable star rating${where}: "${s}" is not a whole 1-5 rating`);
  }
  return Number(s);
}

/**
 * A companion denominator cell. Suppressed or absent yields null, which means
 * "CMS published no sample size" - never "zero patients".
 */
function parseDenominatorCell(raw, label) {
  const s = text(raw);
  if (isSentinel(s)) return null;
  const glued = GLUED_FOOTNOTE_RE.exec(s);
  if (glued && isSentinel(glued[1].trim())) return null;
  const n = toNumber(s);
  if (n === null || !Number.isFinite(n)) {
    throw new QualityParseError(`unparseable denominator${label ? ` for ${label}` : ''}: "${s}"`);
  }
  return n;
}

module.exports = {
  QualityParseError, VALUE_SENTINELS, parseCsv,
  parseScoreCell, parseFootnoteCell, parsePeriodCell, parseStarRatingCell, parseDenominatorCell
};
