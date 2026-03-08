(() => {
  const ADMIN_PATH_RE = /^\/admin/i;
  if (ADMIN_PATH_RE.test(location.pathname)) return;

  const EVENT_URL = '/api/analytics/event';
  const VIEWER_KEY = 'bhhh_viewer_id_v1';
  const SESSION_KEY = 'bhhh_session_id_v1';
  const SCROLL_STEPS = [25, 50, 75, 100];

  let started = false;
  let maxScroll = 0;
  let lastScrollSent = 0;
  const pageStart = Date.now();

  function uid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
  }

  function getViewerId() {
    let id = localStorage.getItem(VIEWER_KEY);
    if (!id) {
      id = uid();
      localStorage.setItem(VIEWER_KEY, id);
    }
    return id;
  }

  function getSessionId() {
    let id = sessionStorage.getItem(SESSION_KEY);
    if (!id) {
      id = uid();
      sessionStorage.setItem(SESSION_KEY, id);
    }
    return id;
  }

  function postEvent(payload, useBeacon = false) {
    const body = JSON.stringify({
      viewerId: getViewerId(),
      sessionId: getSessionId(),
      path: location.pathname,
      referrer: document.referrer || '',
      ...payload
    });

    if (useBeacon && navigator.sendBeacon) {
      const blob = new Blob([body], { type: 'application/json' });
      navigator.sendBeacon(EVENT_URL, blob);
      return;
    }

    fetch(EVENT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      keepalive: true
    }).catch(() => {});
  }

  function computeScrollDepth() {
    const doc = document.documentElement;
    const scrollTop = window.scrollY || doc.scrollTop || 0;
    const maxHeight = Math.max(1, doc.scrollHeight - window.innerHeight);
    return Math.max(0, Math.min(100, Math.round((scrollTop / maxHeight) * 100)));
  }

  function onClick(event) {
    const node = event.target?.closest?.('a,button');
    if (!node) return;
    const text = (node.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 80);
    postEvent({ eventType: 'click', eventValue: text || node.tagName.toLowerCase() });
  }

  function onScroll() {
    const depth = computeScrollDepth();
    if (depth > maxScroll) maxScroll = depth;
    const step = SCROLL_STEPS.find((d) => d > lastScrollSent && depth >= d);
    if (!step) return;
    lastScrollSent = step;
    postEvent({ eventType: 'scroll', scrollDepth: step, eventValue: `${step}%` });
  }

  function onPageHide() {
    postEvent({
      eventType: 'page_exit',
      durationMs: Date.now() - pageStart,
      scrollDepth: maxScroll,
      eventValue: 'page_exit'
    }, true);
  }

  function startTracking() {
    if (started) return;
    started = true;

    postEvent({ eventType: 'page_view', eventValue: document.title.slice(0, 120) });

    document.addEventListener('click', onClick, { passive: true });
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('pagehide', onPageHide);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') onPageHide();
    });

    window.trackBhhhEvent = (eventType, data = {}) => {
      if (!started) return;
      postEvent({ eventType, ...data });
    };
  }

  const consent = localStorage.getItem('bhhh_cookie_consent_v1');
  if (consent === 'granted' || window.bhhhConsentGranted === true) {
    startTracking();
    postEvent({ eventType: 'consent_granted', eventValue: 'stored' });
  }

  window.addEventListener('bhhh:consent', (e) => {
    const state = e?.detail?.state;
    if (state === 'granted') {
      postEvent({ eventType: 'consent_granted', eventValue: 'banner' });
      startTracking();
    }
    if (state === 'denied') {
      postEvent({ eventType: 'consent_declined', eventValue: 'banner' });
    }
  });
})();
