/**
 * First-party lead attribution.
 *
 * Records how a visitor first found Best Hospice and how they arrived most
 * recently, and keeps both. First touch is written once and never overwritten,
 * so a visitor who arrives from Google organic and returns three days later
 * directly still shows google/organic as first touch.
 *
 * Everything is stored in localStorage on our own origin. No third-party
 * cookies, no external calls.
 */
(function () {
  var FIRST_KEY = 'bh_attr_first';
  var LAST_KEY = 'bh_attr_last';
  var OWN_HOST = /(^|\.)besthospice\.com$/i;

  function read(key) {
    try {
      var raw = window.localStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }

  function write(key, value) {
    try { window.localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* private mode */ }
  }

  function param(qs, name) {
    var v = qs.get(name);
    return v ? String(v).trim().slice(0, 255) : null;
  }

  function referrerHost() {
    try { return document.referrer ? new URL(document.referrer).hostname.toLowerCase() : ''; }
    catch (e) { return ''; }
  }

  // A touch worth recording: it carries campaign parameters, a click id, or an
  // external referrer. Plain internal navigation is not a new touch, otherwise
  // clicking through the site would overwrite the real source with "direct".
  function currentTouch() {
    var qs = new URLSearchParams(window.location.search);
    var gclid = param(qs, 'gclid');
    var fbclid = param(qs, 'fbclid');
    var source = param(qs, 'utm_source');
    var medium = param(qs, 'utm_medium');
    var host = referrerHost();
    var external = host && !OWN_HOST.test(host);

    if (!gclid && !fbclid && !source && !medium && !external) return null;

    return {
      source: source,
      medium: medium,
      campaign: param(qs, 'utm_campaign'),
      term: param(qs, 'utm_term'),
      content: param(qs, 'utm_content'),
      gclid: gclid,
      fbclid: fbclid,
      referrer: external ? String(document.referrer).slice(0, 1024) : null,
      landingPage: (window.location.pathname + window.location.search).slice(0, 1024),
      at: new Date().toISOString()
    };
  }

  var touch = currentTouch();

  if (touch) {
    if (!read(FIRST_KEY)) write(FIRST_KEY, touch);
    write(LAST_KEY, touch);
  } else if (!read(FIRST_KEY)) {
    // Genuinely direct arrival with no prior history.
    var direct = {
      source: null, medium: null, campaign: null, term: null, content: null,
      gclid: null, fbclid: null, referrer: null,
      landingPage: (window.location.pathname + window.location.search).slice(0, 1024),
      at: new Date().toISOString()
    };
    write(FIRST_KEY, direct);
    write(LAST_KEY, direct);
  }

  window.bhAttribution = function () {
    var first = read(FIRST_KEY);
    var last = read(LAST_KEY) || first;
    if (!first) return null;
    return {
      first: first,
      last: last,
      gclid: (last && last.gclid) || (first && first.gclid) || null,
      fbclid: (last && last.fbclid) || (first && first.fbclid) || null
    };
  };
})();
