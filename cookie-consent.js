(() => {
  const CONSENT_KEY = 'bhhh_cookie_consent_v1';
  const value = localStorage.getItem(CONSENT_KEY);

  function applyConsent(state) {
    const granted = state === 'granted';
    window.bhhhConsentGranted = granted;
    window.dispatchEvent(new CustomEvent('bhhh:consent', { detail: { state } }));
  }

  if (value === 'granted' || value === 'denied') {
    applyConsent(value);
    return;
  }

  function renderBanner() {
    const bar = document.createElement('div');
    bar.setAttribute('role', 'dialog');
    bar.setAttribute('aria-label', 'Cookie consent');
    bar.setAttribute('aria-live', 'polite');
    Object.assign(bar.style, {
      position: 'fixed',
      left: '16px',
      right: '16px',
      bottom: '16px',
      zIndex: '2147483646',
      background: '#0b1220',
      color: '#fff',
      borderRadius: '12px',
      padding: '12px',
      boxShadow: '0 12px 30px rgba(0,0,0,0.25)',
      fontFamily: 'Sora, Segoe UI, sans-serif',
      fontSize: '14px'
    });

    bar.innerHTML = `
      <div style="display:flex; gap:12px; align-items:flex-start; justify-content:space-between; flex-wrap:wrap;">
        <div style="max-width:780px; line-height:1.45;">
          We use cookies and analytics to improve your experience and measure site performance.
          See our <a href="/privacy.html" style="color:#7dd3fc; text-decoration:underline;">Privacy Policy</a> and
          <a href="/cookie-policy.html" style="color:#7dd3fc; text-decoration:underline;">Cookie Policy</a>.
        </div>
        <div style="display:flex; gap:8px;">
          <button id="bhhh-consent-deny" style="border:1px solid #334155; background:#111827; color:#fff; border-radius:8px; padding:8px 12px; font-weight:600; cursor:pointer;">Decline</button>
          <button id="bhhh-consent-allow" style="border:1px solid #0f766e; background:#0f766e; color:#fff; border-radius:8px; padding:8px 12px; font-weight:700; cursor:pointer;">Accept</button>
        </div>
      </div>
    `;

    document.body.appendChild(bar);

    const acceptBtn = bar.querySelector('#bhhh-consent-allow');
    const denyBtn = bar.querySelector('#bhhh-consent-deny');

    acceptBtn?.addEventListener('click', () => {
      localStorage.setItem(CONSENT_KEY, 'granted');
      applyConsent('granted');
      bar.remove();
    });

    denyBtn?.addEventListener('click', () => {
      localStorage.setItem(CONSENT_KEY, 'denied');
      applyConsent('denied');
      bar.remove();
    });
  }

  window.addEventListener('DOMContentLoaded', renderBanner, { once: true });
})();
