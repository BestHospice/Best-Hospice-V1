const featuredProviders = [
  {
    name: 'Serenity Hospice Care',
    address: '420 Peachtree St NE, Atlanta, GA 30308',
    lat: 33.7725,
    lon: -84.3857,
    serviceRadiusKm: 120
  },
  {
    name: 'HarborLight Hospice',
    address: '845 N Michigan Ave, Chicago, IL 60611',
    lat: 41.8995,
    lon: -87.6244,
    serviceRadiusKm: 90
  },
  {
    name: 'Pacific Comfort Hospice',
    address: '2100 Webster St, Oakland, CA 94612',
    lat: 37.8123,
    lon: -122.2621,
    serviceRadiusKm: 100
  }
];

let providerDirectory = [];
let remoteProvidersLoaded = false;
let turnstileToken = null;
let turnstileWidgetId = null;
let TURNSTILE_SITE_KEY = null;
let pendingCaptchaResolve = null;
let pendingCaptchaReject = null;

let currentNearbyProviders = [];
let currentLeadId = null;
let currentZip = '';
let currentTimeline = '';
let currentContactEmail = '';
let currentContactPhone = '';
let currentContactName = '';
let currentGeoLabel = '';

const map = L.map('map', { scrollWheelZoom: true }).setView([39.5, -98.35], 4);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19,
  attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);
const markers = L.layerGroup().addTo(map);

const resultsList = document.getElementById('results');
const statusEl = document.getElementById('status');
const leadConfirmation = document.getElementById('lead-confirmation');
const notifyMini = document.getElementById('notify-mini');
const mapSection = document.getElementById('map-section');

const reassuranceCard = document.getElementById('reassurance-card');
const reassuranceMessage = document.getElementById('reassurance-message');
const flowContinueBtn = document.getElementById('flow-continue');
const flowSkipBtn = document.getElementById('flow-skip');

const optionalCard = document.getElementById('optional-details-card');
const optionalForm = document.getElementById('optional-details-form');
const detailsSkipBtn = document.getElementById('details-skip');
const detailsStatus = document.getElementById('details-status');
const detailName = document.getElementById('detail-name');
const detailRelationship = document.getElementById('detail-relationship');
const detailCareType = document.getElementById('detail-caretype');
const detailNotes = document.getElementById('detail-notes');
const captchaContainer = document.getElementById('captcha-container');
const noProvidersCard = document.getElementById('no-providers-card');
const noProviderCityEl = document.getElementById('no-provider-city');
const waitlistSubmitBtn = document.getElementById('waitlist-submit');
const waitlistStatusEl = document.getElementById('waitlist-status');

function refreshMapLayout() {
  try {
    requestAnimationFrame(() => map.invalidateSize());
    setTimeout(() => map.invalidateSize(), 120);
    setTimeout(() => map.invalidateSize(), 320);
  } catch (_err) {
    // ignore
  }
}

function setStatus(message, isError = false) {
  if (!statusEl) return;
  statusEl.textContent = isError ? message : '';
  statusEl.style.color = isError ? '#b91c1c' : '#4b5563';
}

function setDetailsStatus(message, isError = false) {
  if (!detailsStatus) return;
  detailsStatus.textContent = message;
  detailsStatus.style.color = isError ? '#b91c1c' : '#4b5563';
}

function websiteAnchor(url) {
  if (!url) return '';
  const trimmed = url.trim();
  const href = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return `<a href="${href}" target="_blank" rel="noopener">Website - click here</a>`;
}

function getPlanBadge(planTier) {
  const tier = String(planTier || '').toLowerCase();
  if (tier === 'priority' || tier === 'market_leader' || tier === 'advanced') return '<span class="badge">⭐⭐⭐ Priority</span>';
  if (tier === 'featured' || tier === 'growth_plus') return '<span class="badge">⭐⭐ Featured</span>';
  if (tier === 'verified' || tier === 'growth' || tier === 'starter') return '<span class="badge">⭐ Verified</span>';
  return '';
}

function formatCareType(value) {
  const type = String(value || '').toLowerCase();
  if (type === 'palliative' || type === 'palliative-care') return 'Palliative Care';
  if (type === 'home' || type === 'home-care') return 'Home Care';
  return 'Hospice Care';
}

function getPlanRank(planTier) {
  const tier = String(planTier || '').toLowerCase();
  if (tier === 'priority' || tier === 'market_leader' || tier === 'advanced') return 3;
  if (tier === 'featured' || tier === 'growth_plus') return 2;
  if (tier === 'verified' || tier === 'growth' || tier === 'starter') return 1;
  return 1;
}

function parseServiceZipCodes(value) {
  return String(value || '')
    .split(/[\s,;\n\r\t]+/)
    .map((z) => z.trim())
    .filter((z) => /^\d{5}$/.test(z));
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = (v) => (v * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function getNearbyProviders(lat, lon, providers, radiusKm, searchZip) {
  return providers
    .map((p) => ({ ...p, distance: haversineKm(lat, lon, p.lat, p.lon) }))
    .filter((p) => {
      const providerRadius = p.serviceRadiusKm || radiusKm;
      const effectiveRadius = Math.min(radiusKm, providerRadius);
      const zipCoverage = parseServiceZipCodes(p.serviceZipCodes);
      const zipMatch = /^\d{5}$/.test(searchZip || '') && zipCoverage.includes(String(searchZip));
      const radiusMatch = p.distance <= effectiveRadius;
      return zipMatch || radiusMatch;
    })
    .sort((a, b) => {
      const rankDiff = getPlanRank(b.planTier) - getPlanRank(a.planTier);
      if (rankDiff !== 0) return rankDiff;
      return (a.distance || 0) - (b.distance || 0);
    });
}

async function geocodeZip(zip) {
  const url = `https://nominatim.openstreetmap.org/search?format=json&postalcode=${encodeURIComponent(zip)}&countrycodes=us&limit=1&addressdetails=1`;
  const response = await fetch(url, { headers: { 'Accept-Language': 'en' } });
  if (!response.ok) throw new Error('ZIP lookup failed');
  const data = await response.json();
  if (!data.length) return null;
  const place = data[0];
  return { lat: parseFloat(place.lat), lon: parseFloat(place.lon), label: place.display_name };
}

async function loadRemoteProviders() {
  if (remoteProvidersLoaded) return;
  const res = await fetch('/api/providers');
  if (!res.ok) throw new Error('Failed to load providers');
  const remote = await res.json();
  providerDirectory = Array.isArray(remote) ? remote : [];
  remoteProvidersLoaded = true;
}

function renderResults(centers, label) {
  resultsList.innerHTML = '';
  markers.clearLayers();
  if (!centers.length) {
    setStatus('No providers found within 60 miles. Try another ZIP.', true);
    return;
  }
  centers.forEach((center, index) => {
    const marker = L.marker([center.lat, center.lon]).addTo(markers);
    const badge = getPlanBadge(center.planTier);
    const contactLines = [];
    if (center.phone) contactLines.push(center.phone);
    if (center.website) contactLines.push(websiteAnchor(center.website));
    if (center.email) contactLines.push(`<a href="mailto:${center.email}">${center.email}</a>`);
    const careLine = center.careType ? `<br><em>${formatCareType(center.careType)}</em>` : '';
    marker.bindPopup(
      `<strong>${center.name}</strong><br>${center.address || 'Address not listed'}${careLine}${badge ? '<br><em>Partner provider</em>' : ''}<br>${contactLines.join(' | ')}`
    );

    const item = document.createElement('li');
    item.className = 'result';
    const milesAway = center.distance ? (center.distance * 0.621371).toFixed(1) + ' mi away' : '';
    item.innerHTML = `
      <p class="result-title">${index + 1}. ${center.name} ${badge}</p>
      <p class="result-meta">
        ${center.careType ? `<span>${formatCareType(center.careType)}</span>` : ''}
        <span>${center.address || 'Address not listed'}</span>
        <span>${milesAway}</span>
        ${center.phone ? `<span>Phone: <a href="tel:${center.phone}">${center.phone}</a></span>` : ''}
        ${center.email ? `<span>Email: <a href="mailto:${center.email}">${center.email}</a></span>` : ''}
        ${center.website ? `<span>${websiteAnchor(center.website)}</span>` : ''}
      </p>
    `;
    item.addEventListener('mouseenter', () => marker.openPopup());
    item.addEventListener('mouseleave', () => marker.closePopup());
    item.addEventListener('click', () => {
      map.setView([center.lat, center.lon], 15, { animate: true });
      marker.openPopup();
    });
    resultsList.appendChild(item);
  });
  setStatus(`${centers.length} verified hospice, palliative, and home care providers serve your area (${label}).`);
}

async function loadTurnstileSiteKey() {
  try {
    const res = await fetch('/api/config/turnstile');
    if (!res.ok) throw new Error('No captcha config');
    const data = await res.json();
    TURNSTILE_SITE_KEY = data.siteKey;
  } catch (_err) {
    TURNSTILE_SITE_KEY = null;
  }
}

function ensureCaptchaWidget() {
  if (!TURNSTILE_SITE_KEY || !window.turnstile) return;
  if (turnstileWidgetId) return;
  captchaContainer.classList.remove('hidden');
  turnstileWidgetId = window.turnstile.render('#turnstile-widget', {
    sitekey: TURNSTILE_SITE_KEY,
    callback: function (token) {
      turnstileToken = token;
      if (pendingCaptchaResolve) {
        pendingCaptchaResolve(token);
        pendingCaptchaResolve = null;
        pendingCaptchaReject = null;
      }
    },
    'error-callback': function () {
      if (pendingCaptchaReject) pendingCaptchaReject(new Error('Captcha failed'));
    },
    'expired-callback': function () {
      turnstileToken = null;
    }
  });
}

async function getCaptchaToken() {
  if (!TURNSTILE_SITE_KEY) throw new Error('Captcha not configured');
  if (turnstileToken) return turnstileToken;
  ensureCaptchaWidget();
  setStatus('Please complete the verification to notify providers.');
  return new Promise((resolve, reject) => {
    pendingCaptchaResolve = resolve;
    pendingCaptchaReject = reject;
  });
}

function splitName(fullName) {
  const clean = String(fullName || '').trim();
  if (!clean) return { firstName: '', lastName: '' };
  const parts = clean.split(/\s+/);
  return {
    firstName: parts[0] || '',
    lastName: parts.slice(1).join(' ')
  };
}

function extractCityFromLabel(label, zip) {
  const parts = String(label || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (!parts.length) return 'your area';
  const zipStr = String(zip || '').trim();
  for (const part of parts) {
    if (part === zipStr || /^\d{5}$/.test(part)) continue;
    if (/county/i.test(part)) continue;
    if (/united states/i.test(part)) continue;
    return part;
  }
  return parts[0] || 'your area';
}

function revealFinalScreen() {
  reassuranceCard?.classList.add('hidden');
  optionalCard?.classList.add('hidden');
  noProvidersCard?.classList.add('hidden');
  mapSection.classList.remove('hidden');
  leadConfirmation.textContent =
    "You're all set! The providers below have been notified and are ready to help. Expect to hear from them soon. Browse their profiles below to learn more about who will be reaching out.";
  leadConfirmation.classList.remove('hidden');
  if (notifyMini.textContent.trim()) notifyMini.classList.remove('hidden');
  refreshMapLayout();
  mapSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showResultsWithOptionalPrompt() {
  reassuranceCard?.classList.add('hidden');
  noProvidersCard?.classList.add('hidden');
  mapSection.classList.remove('hidden');
  optionalCard?.classList.remove('hidden');
  leadConfirmation.textContent =
    "You're all set! The providers below have been notified and are ready to help. Expect to hear from them soon. Browse their profiles below to learn more about who will be reaching out.";
  leadConfirmation.classList.remove('hidden');
  if (notifyMini.textContent.trim()) notifyMini.classList.remove('hidden');
  if (typeof window.trackBhhhEvent === 'function') {
    window.trackBhhhEvent('search_results_loaded', {
      eventValue: 'results_with_optional_prompt',
      metadata: { providers: currentNearbyProviders.length, zip: currentZip }
    });
  }
  refreshMapLayout();
  optionalCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showNoProvidersState(cityName) {
  reassuranceCard?.classList.add('hidden');
  optionalCard?.classList.add('hidden');
  mapSection.classList.add('hidden');
  if (noProviderCityEl) noProviderCityEl.textContent = cityName || 'your area';
  if (waitlistStatusEl) waitlistStatusEl.textContent = '';
  noProvidersCard?.classList.remove('hidden');
  if (typeof window.trackBhhhEvent === 'function') {
    window.trackBhhhEvent('search_results_loaded', {
      eventValue: 'no_providers',
      metadata: { city: cityName || 'unknown', zip: currentZip }
    });
  }
  noProvidersCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toRelationshipValue(inputValue) {
  if (inputValue === 'me') return 'me';
  if (inputValue === 'loved-one') return 'loved-one';
  if (inputValue === 'spouse') return 'loved-one';
  return 'other';
}

async function notifyInitialLead() {
  const nameParts = splitName(currentContactName);
  const res = await fetch('/api/notify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      mode: 'initial',
      zip: currentZip,
      providers: currentNearbyProviders.map((p) => ({
        id: p.id,
        name: p.name,
        address: p.address,
        email: p.email,
        phone: p.phone || '',
        website: p.website || '',
        lat: p.lat,
        lon: p.lon,
        planTier: p.planTier
      })),
      answers: {
        timeline: currentTimeline,
        contactEmail: currentContactEmail,
        contactPhone: currentContactPhone || '',
        relationship: 'me',
        fullName: {
          first: nameParts.firstName,
          last: nameParts.lastName
        }
      },
      captchaToken: turnstileToken
    })
  });
  if (!res.ok) throw new Error('Initial notify failed');
  return res.json();
}

async function notifyEnhancedDetails(detailsAnswers) {
  const res = await fetch('/api/notify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      mode: 'details',
      leadId: currentLeadId,
      zip: currentZip,
      providers: currentNearbyProviders.map((p) => ({
        id: p.id,
        name: p.name,
        address: p.address,
        email: p.email,
        phone: p.phone || '',
        website: p.website || '',
        lat: p.lat,
        lon: p.lon,
        planTier: p.planTier
      })),
      answers: detailsAnswers
    })
  });
  if (!res.ok) throw new Error('Enhanced details notify failed');
  return res.json();
}

async function handleOptionalDetailsSubmit(event) {
  event.preventDefault();
  if (!currentNearbyProviders.length || !currentLeadId) {
    setDetailsStatus('Please run a provider search first.', true);
    return;
  }
  if (!detailRelationship.value || !detailCareType.value) {
    setDetailsStatus('Please select who needs care and care type.', true);
    return;
  }

  const nameParts = splitName(detailName.value);
  const answers = {
    relationship: toRelationshipValue(detailRelationship.value),
    careType: [detailCareType.value],
    services: [],
    moreDetails: detailNotes.value.trim() || '',
    contactEmail: currentContactEmail,
    contactPhone: currentContactPhone,
    timeline: currentTimeline,
    fullName: {
      first: nameParts.firstName,
      last: nameParts.lastName
    }
  };

  try {
    setDetailsStatus('Sending additional details...');
    await notifyEnhancedDetails(answers);
    if (typeof window.trackBhhhEvent === 'function') {
      window.trackBhhhEvent('form_submit_details', {
        eventValue: 'optional_details_submitted',
        metadata: { careType: detailCareType.value || '', relationship: detailRelationship.value || '' }
      });
    }
    setDetailsStatus('Thank you! Providers now have more details to assist you.');
    revealFinalScreen();
  } catch (err) {
    console.error(err);
    setDetailsStatus('Could not send additional details. Please try again.', true);
  }
}

async function startResultsFlow() {
  try {
    const params = new URLSearchParams(window.location.search);
    currentZip = (params.get('zip') || '').trim();
    currentTimeline = (params.get('timeline') || '').trim();
    currentContactEmail = (params.get('contactEmail') || '').trim();
    currentContactPhone = (params.get('contactPhone') || '').trim();
    currentContactName = (params.get('contactName') || '').trim();

    if (!/^\d{5}$/.test(currentZip) || !currentTimeline || !currentContactEmail) {
      setStatus('Missing required search details. Please start again.', true);
      reassuranceCard.classList.remove('hidden');
      reassuranceMessage.textContent = 'Please return to the search page and complete ZIP code, timeline, and email.';
      flowContinueBtn.textContent = 'Back to Search';
      flowSkipBtn.classList.add('hidden');
      flowContinueBtn.addEventListener('click', () => {
        window.location.href = 'search.html';
      });
      return;
    }

    reassuranceCard.classList.remove('hidden');
    reassuranceMessage.textContent = 'We are matching providers in your area now...';
    setStatus('Searching local providers...');

    const geo = await geocodeZip(currentZip);
    if (!geo) {
      setStatus('Could not find that ZIP. Please try again.', true);
      reassuranceMessage.textContent = 'We could not find that ZIP code. Please go back and try another one.';
      return;
    }
    currentGeoLabel = geo.label || '';

    const radiusKm = 96.6;
    await loadRemoteProviders();
    const directoryHits = getNearbyProviders(geo.lat, geo.lon, providerDirectory, radiusKm, currentZip);

    const merged = [
      ...directoryHits,
      ...featuredProviders
        .map((p) => ({
          ...p,
          distance: haversineKm(geo.lat, geo.lon, p.lat, p.lon),
          source: 'featured'
        }))
        .filter((p) => p.distance <= Math.min(radiusKm, p.serviceRadiusKm || radiusKm))
    ];

    const unique = [];
    const seen = new Set();
    for (const p of merged) {
      const key = `${p.name}-${p.lat}-${p.lon}`;
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(p);
    }
    unique.sort((a, b) => {
      const rankDiff = getPlanRank(b.planTier) - getPlanRank(a.planTier);
      if (rankDiff !== 0) return rankDiff;
      return (a.distance || 0) - (b.distance || 0);
    });

    currentNearbyProviders = unique.filter((p) => !!p.id && !!p.email);
    map.setView([geo.lat, geo.lon], 11);
    const cityName = extractCityFromLabel(geo.label, currentZip);
    if (!currentNearbyProviders.length) {
      showNoProvidersState(cityName);
      setStatus('', false);
      return;
    }

    renderResults(unique, geo.label);

    await getCaptchaToken();
    const initialResult = await notifyInitialLead();
    currentLeadId = initialResult.leadId || null;

    const contactTarget = currentContactPhone
      ? `${currentContactPhone} or ${currentContactEmail}`
      : currentContactEmail;

    reassuranceMessage.textContent = `We've notified ${currentNearbyProviders.length} verified hospice providers near ${cityName} and they will be reaching out to you shortly at ${contactTarget}. Most families hear back within a few hours.`;
    notifyMini.textContent = `We've notified ${currentNearbyProviders.length} matched providers near ${cityName}.`;
    setStatus(`We've notified ${currentNearbyProviders.length} providers near ${geo.label}.`);
    showResultsWithOptionalPrompt();
  } catch (err) {
    console.error(err);
    setStatus('Unable to complete search right now. Please try again.', true);
  }
}

flowContinueBtn?.addEventListener('click', () => {
  reassuranceCard?.classList.add('hidden');
  optionalCard?.classList.remove('hidden');
  optionalCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

flowSkipBtn?.addEventListener('click', () => {
  revealFinalScreen();
});

detailsSkipBtn?.addEventListener('click', () => {
  revealFinalScreen();
});

waitlistSubmitBtn?.addEventListener('click', async () => {
  waitlistStatusEl.textContent = 'Submitting...';
  waitlistStatusEl.style.color = '#4b5563';
  try {
    const cityName = extractCityFromLabel(currentGeoLabel, currentZip);
    const res = await fetch('/api/waitlist/notify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        zip: currentZip,
        city: cityName,
        timeline: currentTimeline,
        contactEmail: currentContactEmail,
        contactPhone: currentContactPhone
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Could not submit request');
    waitlistStatusEl.textContent = 'Thank you. We will notify you when coverage is available in your area.';
    waitlistStatusEl.style.color = '#0f766e';
  } catch (err) {
    waitlistStatusEl.textContent = err.message || 'Could not submit request right now.';
    waitlistStatusEl.style.color = '#b91c1c';
  }
});

optionalForm?.addEventListener('submit', handleOptionalDetailsSubmit);

function injectMainMenuButton() {
  if (document.getElementById('main-menu-btn')) return;
  const btn = document.createElement('a');
  btn.id = 'main-menu-btn';
  btn.href = '/';
  btn.textContent = 'Main Menu';
  Object.assign(btn.style, {
    position: 'fixed',
    right: '16px',
    bottom: '16px',
    padding: '10px 14px',
    background: '#0f766e',
    color: '#fff',
    borderRadius: '999px',
    fontWeight: '700',
    boxShadow: '0 10px 18px rgba(0,0,0,0.12)',
    textDecoration: 'none',
    zIndex: '9999'
  });
  document.body.appendChild(btn);
}

window.addEventListener('load', injectMainMenuButton);
window.addEventListener('resize', refreshMapLayout);

(async () => {
  await loadTurnstileSiteKey();
  await startResultsFlow();
})();
