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

const questions = [
  {
    id: 'fullName',
    title: 'What is your first and last name?',
    desc: 'So providers know who to address',
    type: 'name'
  },
  {
    id: 'relationship',
    title: 'Who is this care for?',
    desc: 'Choose one',
    type: 'select',
    options: [
      { value: 'me', label: 'Me' },
      { value: 'loved-one', label: 'Loved one' },
      { value: 'other', label: 'Other' }
    ]
  },
  {
    id: 'frequency',
    title: 'How often do they need care?',
    desc: 'Pick days and times that apply',
    type: 'frequency',
    days: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'],
    times: ['Morning', 'Afternoon', 'Night', 'All day', '24/7', '24/5 (Weekdays only)', '24/2 (Weekends only)']
  },
  {
    id: 'services',
    title: 'What do you need help with?',
    desc: 'Select all that apply — this helps match you with the right hospice, palliative, or home care support',
    type: 'checklist',
    groups: [
      {
        title: 'Care & Comfort',
        items: [
          'Pain or symptom relief (breathing, nausea, anxiety)',
          'Medication help or management',
          'Emotional or mental health support'
        ]
      },
      {
        title: 'Personal & Daily Care',
        items: [
          'Bathing, hygiene, or mobility help',
          'Feeding, toileting, or wound care'
        ]
      },
      {
        title: 'Medical Equipment & Supplies',
        items: [
          'Hospital bed, oxygen, wheelchair, or supplies'
        ]
      },
      {
        title: 'Family & Caregiver Support',
        items: [
          'Education on caregiving or what to expect',
          'Help during advanced illness or end-of-life'
        ]
      },
      {
        title: 'Care Coordination',
        items: [
          'Support coordinating doctors, medications, or care plans',
          'Help with advance directives or planning'
        ]
      },
      {
        title: 'Spiritual & Cultural Support',
        items: [
          'Chaplain, faith-based, or cultural support'
        ]
      }
    ]
  },
  {
    id: 'funding',
    title: 'How do you plan to fund care?',
    desc: 'Choose one',
    type: 'select',
    options: [
      { value: 'medicare', label: 'Medicare' },
      { value: 'va', label: 'Veterans (VA)' },
      { value: 'medicaid', label: 'Medicaid' },
      { value: 'private', label: 'Private' },
      { value: 'commercial', label: 'Commercial Insurer' },
      { value: 'medicare-advantage', label: 'Medicare Advantage' },
      { value: 'other', label: 'Other' }
    ]
  },
  {
    id: 'moreDetails',
    title: 'If you have more specific needs or want to allow us to decide what care is best, type your situation below',
    desc: 'Optional: share anything unique about your situation to better inform Best Hospice providers',
    type: 'textarea'
  },
  {
    id: 'contactEmail',
    title: 'Where can providers reach you?',
    desc: 'Add your email so nearby hospice teams can reply',
    type: 'email'
  },
  {
    id: 'contactPhone',
    title: 'What is your phone number?',
    desc: 'Providers can call if email is missed.',
    type: 'phone'
  }
];

let providerDirectory = [];

const userResponses = { zip: '', answers: {} };
let currentQuestion = 0;
let remoteProvidersLoaded = false;
let turnstileToken = null;
let turnstileWidgetId = null;
let pendingZip = null;
let TURNSTILE_SITE_KEY = null;

const map = L.map('map', { scrollWheelZoom: true }).setView([39.5, -98.35], 4);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19,
  attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

const markers = L.layerGroup().addTo(map);
const form = document.getElementById('search-form');
const zipInput = document.getElementById('zip');
const captchaContainer = document.getElementById('captcha-container');
const turnstileDiv = document.getElementById('turnstile-widget');
const resultsList = document.getElementById('results');
const statusEl = document.getElementById('status');
const questionnaire = document.getElementById('questionnaire');
const questionForm = document.getElementById('question-form');
const questionContent = document.getElementById('question-content');
const questionTitle = document.getElementById('question-title');
const questionDesc = document.getElementById('question-desc');
const questionProgress = document.getElementById('question-progress');
const backBtn = document.getElementById('back-btn');
const mapSection = document.getElementById('map-section');
const summarySection = document.getElementById('summary-section');
const summaryContent = document.getElementById('summary-content');
const summaryEmail = document.getElementById('summary-email');
const privacySection = document.getElementById('privacy-section');
const privacyAck = document.getElementById('privacy-ack');
const privacyContinue = document.getElementById('privacy-continue');

async function loadTurnstileSiteKey() {
  try {
    const res = await fetch('/api/config/turnstile');
    if (!res.ok) throw new Error('Failed to load captcha config');
    const data = await res.json();
    TURNSTILE_SITE_KEY = data.siteKey;
  } catch (err) {
    console.warn('Could not load Turnstile site key', err);
    TURNSTILE_SITE_KEY = null;
  }
}

loadTurnstileSiteKey();

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const zip = zipInput.value.trim();
  if (!/^\d{5}$/.test(zip)) {
    setStatus('Enter a 5-digit ZIP code.', true);
    return;
  }
  // reset captcha state per attempt
  turnstileToken = null;
  pendingZip = zip;
  if (!TURNSTILE_SITE_KEY) {
    setStatus('Captcha is not ready. Please try again in a moment.', true);
    return;
  }
  if (!turnstileWidgetId && window.turnstile) {
    captchaContainer.classList.remove('hidden');
    turnstileWidgetId = window.turnstile.render('#turnstile-widget', {
      sitekey: TURNSTILE_SITE_KEY,
      callback: function (token) {
        turnstileToken = token;
        if (pendingZip) {
          userResponses.zip = pendingZip;
          userResponses.answers = {};
          currentQuestion = 0;
          pendingZip = null;
          captchaContainer.classList.add('hidden');
          showPrivacyNotice();
        }
      },
      'error-callback': function () {
        turnstileToken = null;
      },
      'expired-callback': function () {
        turnstileToken = null;
      }
    });
    setStatus('Please complete the captcha to continue.');
    return;
  }
  if (!turnstileToken) {
    captchaContainer.classList.remove('hidden');
    setStatus('Please complete the captcha to continue.', true);
    return;
  }
  userResponses.zip = zip;
  userResponses.answers = {};
  currentQuestion = 0;
  pendingZip = null;
  showQuestionnaire();
});

questionForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const q = questions[currentQuestion];
  const answer = collectAnswer(q);
  const isEmpty = !answer || (Array.isArray(answer) && answer.length === 0);
  if (isEmpty) {
    // Allow optional free-text to be skipped
    if (q.id === 'moreDetails') {
      userResponses.answers[q.id] = '';
    } else {
      return;
    }
  } else {
    userResponses.answers[q.id] = answer;
  }
  currentQuestion += 1;
  if (currentQuestion >= questions.length) {
    finishQuestions();
  } else {
    renderQuestion();
  }
});

backBtn.addEventListener('click', () => {
  if (currentQuestion === 0) return;
  currentQuestion -= 1;
  renderQuestion();
});

function showQuestionnaire() {
  questionnaire.classList.remove('hidden');
  mapSection.classList.add('hidden');
  summarySection.classList.add('hidden');
  renderQuestion();
  questionnaire.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showPrivacyNotice() {
  privacySection.classList.remove('hidden');
  questionnaire.classList.add('hidden');
  mapSection.classList.add('hidden');
  summarySection.classList.add('hidden');
  privacySection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

privacyAck?.addEventListener('change', () => {
  privacyContinue.disabled = !privacyAck.checked;
});

privacyContinue?.addEventListener('click', () => {
  if (!privacyAck.checked) return;
  privacySection.classList.add('hidden');
  showQuestionnaire();
});

function websiteAnchor(url) {
  if (!url) return '';
  const trimmed = url.trim();
  const href = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const label = href.replace(/^https?:\/\//i, '').replace(/\/$/, '');
  return `<a href="${href}" target="_blank" rel="noopener">${label}</a>`;
}

async function finishQuestions() {
  questionnaire.classList.add('hidden');
  mapSection.classList.remove('hidden');
  summarySection.classList.remove('hidden');
  resultsList.innerHTML = '';
  markers.clearLayers();

  const zip = userResponses.zip;
  setStatus('Looking up ZIP location…');

  try {
    const geo = await geocodeZip(zip);
    if (!geo) {
      setStatus('Could not find that ZIP. Try another.', true);
      return;
    }

    const { lat, lon, label } = geo;
    map.setView([lat, lon], 11);
    map.whenReady(() => map.invalidateSize());

    const radiusKm = 96.6; // ~60 miles
    let centers = [];
    try {
      await loadRemoteProviders();
      centers = await fetchHospiceCenters(lat, lon, radiusKm);
    } catch (err) {
      console.warn('Lookup failed, falling back to featured/directory only', err);
      centers = [];
    }

    // Always ensure we show directory/featured providers even if Overpass fails
    const directoryFallback = getNearbyProviders(lat, lon, providerDirectory, radiusKm).map((p) => ({
      name: p.name,
      address: p.address,
      lat: p.lat,
      lon: p.lon,
      distance: p.distance,
      source: 'directory',
      email: p.email,
      phone: p.phone,
      website: p.website
    }));
    if (!centers.length) {
      centers = directoryFallback;
    } else {
      // merge in any directory providers not already included
      const existing = new Set(centers.map((c) => `${c.name}-${c.lat}-${c.lon}`));
      directoryFallback.forEach((p) => {
        const key = `${p.name}-${p.lat}-${p.lon}`;
        if (!existing.has(key)) centers.push(p);
      });
      centers.sort((a, b) => (a.distance || 0) - (b.distance || 0));
    }

    if (!centers.length) {
      setStatus('No hospice providers within 60 miles. Try another ZIP or pan the map.', true);
    } else {
    centers.forEach((center, index) => {
      const marker = L.marker([center.lat, center.lon]).addTo(markers);
      const badge = center.source === 'featured' ? '<span class="badge">Verified ★</span>' : '';
      const contactLines = [];
      if (center.phone) contactLines.push(center.phone);
      if (center.website) contactLines.push(`Website: ${websiteAnchor(center.website)}`);
      if (center.email) contactLines.push(`<a href="mailto:${center.email}">${center.email}</a>`);
      const contactBlock = contactLines.length ? `<br>${contactLines.join(' | ')}` : '';
      const content = `<strong>${center.name}</strong><br>${center.address || 'Address not listed'}${badge ? '<br><em>Partner hospice</em>' : ''}${contactBlock}`;
      marker.bindPopup(content);

      const item = document.createElement('li');
      item.className = 'result';
      const milesAway = center.distance ? (center.distance * 0.621371).toFixed(1) + ' mi away' : '';
      item.innerHTML = `
        <p class="result-title">${index + 1}. ${center.name} ${badge}</p>
        <p class="result-meta">
          <span>${center.address || 'Address not listed'}</span>
          <span>${milesAway}</span>
          ${center.phone ? `<span>Phone: <a href="tel:${center.phone}">${center.phone}</a></span>` : ''}
          ${center.email ? `<span>Email: <a href="mailto:${center.email}">${center.email}</a></span>` : ''}
          ${center.website ? `<span>Website: ${websiteAnchor(center.website)}</span>` : ''}
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

      setStatus(`Showing ${centers.length} hospice providers near ${label}.`);
    }

    const nearbyProviders = getNearbyProviders(lat, lon, providerDirectory, 96.6);
    renderSummary(centers || [], label, nearbyProviders);
    if (nearbyProviders.length) {
      setStatus(`Showing ${centers.length} hospice providers near ${label}. Sending your request...`);
      try {
        const notified = await notifyProviders(userResponses.zip, nearbyProviders, userResponses.answers);
        setStatus(`Showing ${centers.length} hospice providers near ${label}. Notified ${notified} provider${notified === 1 ? '' : 's'}.`);
      } catch (err) {
        console.warn('Notify failed', err);
        setStatus(`Showing ${centers.length} hospice providers near ${label}. Unable to send automatically.`, true);
      }
    }
    mapSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    console.error(error);
    setStatus('Something went wrong. Please try again.', true);
  }
}

function renderQuestion() {
  const q = questions[currentQuestion];
  questionTitle.textContent = q.title;
  questionDesc.textContent = q.desc;
  questionProgress.textContent = `Question ${currentQuestion + 1} of ${questions.length}`;
  questionContent.innerHTML = '';

  if (q.type === 'select') {
    const grid = document.createElement('div');
    grid.className = 'option-grid';
    q.options.forEach((opt) => {
      const card = document.createElement('div');
      card.className = 'option-card';
      card.textContent = opt.label;
      card.dataset.value = opt.value;
      if (userResponses.answers[q.id] === opt.value) card.classList.add('active');
      card.addEventListener('click', () => {
        questionContent.querySelectorAll('.option-card').forEach((c) => c.classList.remove('active'));
        card.classList.add('active');
      });
      grid.appendChild(card);
    });
    questionContent.appendChild(grid);
  }

  if (q.type === 'frequency') {
    const daysWrap = document.createElement('div');
    daysWrap.className = 'pill-grid';
    daysWrap.dataset.group = 'days';
    q.days.forEach((day) => {
      const pill = document.createElement('div');
      pill.className = 'pill-option';
      pill.textContent = day;
      pill.dataset.value = day;
      if (userResponses.answers[q.id]?.days?.includes(day)) pill.classList.add('active');
      pill.addEventListener('click', () => pill.classList.toggle('active'));
      daysWrap.appendChild(pill);
    });
    questionContent.appendChild(labelBlock('Days needed', daysWrap));

    const timesWrap = document.createElement('div');
    timesWrap.className = 'pill-grid';
    timesWrap.dataset.group = 'times';
    q.times.forEach((time) => {
      const pill = document.createElement('div');
      pill.className = 'pill-option';
      pill.textContent = time;
      pill.dataset.value = time;
      if (userResponses.answers[q.id]?.times?.includes(time)) pill.classList.add('active');
      pill.addEventListener('click', () => pill.classList.toggle('active'));
      timesWrap.appendChild(pill);
    });
    questionContent.appendChild(labelBlock('Times of day', timesWrap));
  }

  if (q.type === 'checklist') {
    const list = document.createElement('div');
    list.className = 'checklist';
    q.groups.forEach((group, idx) => {
      const section = document.createElement('div');
      section.className = 'checklist-group';
      const h = document.createElement('h4');
      h.textContent = `${idx + 1}. ${group.title}`;
      const p = document.createElement('p');
      p.textContent = group.subtitle;
      section.appendChild(h);
      section.appendChild(p);
      const opts = document.createElement('div');
      opts.className = 'checklist-options';
      group.items.forEach((item, i) => {
        const id = `${group.title}-${i}`.replace(/\s+/g, '-');
        const label = document.createElement('label');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = item;
        checkbox.id = id;
        if (userResponses.answers[q.id]?.includes(item)) checkbox.checked = true;
        const textWrap = document.createElement('div');
        const main = document.createElement('span');
        main.textContent = item;
        textWrap.appendChild(main);
        label.appendChild(checkbox);
        label.appendChild(textWrap);
        opts.appendChild(label);
      });
      section.appendChild(opts);
      list.appendChild(section);
    });
    questionContent.appendChild(list);
  }

  if (q.type === 'email') {
    const input = document.createElement('input');
    input.type = 'email';
    input.required = true;
    input.placeholder = 'you@example.com';
    input.className = 'input-text';
    input.value = userResponses.answers[q.id] || '';
    questionContent.appendChild(input);
  }
  if (q.type === 'phone') {
    const input = document.createElement('input');
    input.type = 'tel';
    input.placeholder = '(555) 123-4567';
    input.className = 'input-text';
    input.value = userResponses.answers[q.id] || '';
    questionContent.appendChild(input);
  }
  if (q.type === 'textarea') {
    const area = document.createElement('textarea');
    area.rows = 4;
    area.placeholder = 'Tell us anything else that would help match care to your needs';
    area.className = 'input-text';
    area.value = userResponses.answers[q.id] || '';
    questionContent.appendChild(area);
  }
  if (q.type === 'name') {
    const grid = document.createElement('div');
    grid.className = 'option-grid';
    const first = document.createElement('input');
    first.type = 'text';
    first.placeholder = 'First name';
    first.className = 'input-text';
    const last = document.createElement('input');
    last.type = 'text';
    last.placeholder = 'Last name';
    last.className = 'input-text';
    const prior = userResponses.answers[q.id];
    if (prior?.first) first.value = prior.first;
    if (prior?.last) last.value = prior.last;
    grid.appendChild(first);
    grid.appendChild(last);
    questionContent.appendChild(grid);
  }
  if (q.type === 'text') {
    const input = document.createElement('input');
    input.type = 'text';
    input.required = true;
    input.className = 'input-text';
    input.value = userResponses.answers[q.id] || '';
    questionContent.appendChild(input);
  }

  backBtn.disabled = currentQuestion === 0;
}

function collectAnswer(question) {
  if (question.type === 'select') {
    const active = questionContent.querySelector('.option-card.active');
    return active ? active.dataset.value : null;
  }
  if (question.type === 'frequency') {
    const days = Array.from(questionContent.querySelectorAll('[data-group="days"] .pill-option.active')).map((p) => p.dataset.value);
    const times = Array.from(questionContent.querySelectorAll('[data-group="times"] .pill-option.active')).map((p) => p.dataset.value);
    return { days, times };
  }
  if (question.type === 'checklist') {
    const checked = Array.from(questionContent.querySelectorAll('input[type="checkbox"]:checked')).map((c) => c.value);
    return checked;
  }
  if (question.type === 'email') {
    const emailInput = questionContent.querySelector('input[type="email"]');
    return emailInput?.value.trim();
  }
  if (question.type === 'phone') {
    const phoneInput = questionContent.querySelector('input[type="tel"]');
    return phoneInput?.value.trim();
  }
  if (question.type === 'textarea') {
    const area = questionContent.querySelector('textarea');
    return area?.value.trim();
  }
  if (question.type === 'text') {
    const input = questionContent.querySelector('input[type="text"]');
    return input?.value.trim();
  }
  if (question.type === 'name') {
    const inputs = questionContent.querySelectorAll('input[type="text"]');
    const first = inputs[0]?.value.trim();
    const last = inputs[1]?.value.trim();
    if (!first && !last) return null;
    return { first, last };
  }
  return null;
}

function renderSummary(centers, label, nearbyProviders) {
  summaryContent.innerHTML = '';
  const answers = userResponses.answers;
  const list = document.createElement('ul');
  list.className = 'summary-list';

  const addItem = (title, value) => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${title}:</strong> ${value}`;
    list.appendChild(li);
  };

  addItem('ZIP code', userResponses.zip);
  addItem('Name', answers.fullName ? `${answers.fullName.first || ''} ${answers.fullName.last || ''}`.trim() || 'Not provided' : 'Not provided');
  addItem('Who needs care', prettyRelationship(answers.relationship));
  const freqDays = answers.frequency?.days?.join(', ') || 'Not specified';
  const freqTimes = answers.frequency?.times?.join(', ') || 'Not specified';
  addItem('Care days', freqDays);
  addItem('Care times', freqTimes);
  addItem('Selected services', answers.services?.join('; ') || 'Not specified');
  addItem('Other services or notes', answers.moreDetails || 'Not provided');
  addItem('Funding', prettyFunding(answers.funding));
  addItem('Contact email', answers.contactEmail || 'Not provided');
  addItem('Contact phone', answers.contactPhone || 'Not provided');

  summaryContent.appendChild(list);

  const providerBlock = document.createElement('div');
  providerBlock.className = 'summary-nearby';
  const providerHeading = document.createElement('h4');
  providerHeading.textContent = 'Here are the providers you can contact in your area, they will likely reach out to you shortly!';
  providerBlock.appendChild(providerHeading);
  if (nearbyProviders.length) {
    const ul = document.createElement('ul');
    nearbyProviders.forEach((p) => {
      const li = document.createElement('li');
      li.textContent = `${p.name} — ${p.email}`;
      ul.appendChild(li);
    });
    providerBlock.appendChild(ul);
  } else {
    const none = document.createElement('p');
    none.textContent = 'No providers in range to email.';
    providerBlock.appendChild(none);
  }
  summaryContent.appendChild(providerBlock);

  const subject = encodeURIComponent(`Hospice inquiry near ${userResponses.zip}`);
  const bodyLines = [
    `ZIP code: ${userResponses.zip}`,
    `Client name: ${answers.fullName ? `${answers.fullName.first || ''} ${answers.fullName.last || ''}`.trim() : ''}`,
    `Who needs care: ${prettyRelationship(answers.relationship)}`,
    `Care days: ${freqDays}`,
    `Care times: ${freqTimes}`,
    `Services: ${answers.services?.join('; ') || 'Not specified'}`,
    `Funding: ${prettyFunding(answers.funding)}`,
    `Client contact email: ${answers.contactEmail || 'Not provided'}`,
    `Client phone: ${answers.contactPhone || 'Not provided'}`,
    `Other services or notes: ${answers.moreDetails || 'Not provided'}`,
    '',
    'We support care that acts quickly at Best Hospice. We encourage you to reach out promptly!',
    'Thank you for being a valued member of Best Hospice and for providing compassionate care during life’s most difficult moments.'
  ];

  const toList = nearbyProviders.length ? nearbyProviders.map((p) => p.email).join(',') : '';
  const mailto = `mailto:${encodeURIComponent(toList || 'providers@besthospice.com')}?subject=${subject}&body=${encodeURIComponent(bodyLines.join('\n'))}`;
  summaryEmail.href = mailto;
  summaryEmail.textContent = 'Email this summary';
  summaryEmail.classList.remove('disabled');
}

function prettyRelationship(value) {
  if (value === 'me') return 'Me';
  if (value === 'loved-one') return 'Loved one';
  if (value === 'other') return 'Other';
  return 'Not specified';
}

function prettyFunding(value) {
  switch (value) {
    case 'medicare':
      return 'Medicare';
    case 'va':
      return 'Veterans (VA)';
    case 'medicaid':
      return 'Medicaid';
    case 'private':
      return 'Private';
    case 'commercial':
      return 'Commercial Insurer';
    case 'medicare-advantage':
      return 'Medicare Advantage';
    case 'other':
      return 'Other / Not specified';
    default:
      return 'Not specified';
  }
}

// Global "Main Menu" button on pages loading this script
function injectMainMenuButton() {
  try {
    if (document.getElementById('main-menu-btn')) return;
    const btn = document.createElement('a');
    btn.id = 'main-menu-btn';
    btn.href = 'index.html';
    btn.textContent = 'Main Menu';
    Object.assign(btn.style, {
      position: 'fixed',
      right: '16px',
      bottom: '16px',
      padding: '10px 14px',
      background: '#1d4ed8',
      color: '#fff',
      borderRadius: '999px',
      fontWeight: '700',
      boxShadow: '0 10px 18px rgba(0,0,0,0.12)',
      textDecoration: 'none',
      zIndex: '9999'
    });
    document.body.appendChild(btn);
  } catch (e) {
    // ignore if it fails; not critical
  }
}

window.addEventListener('load', injectMainMenuButton);

function labelBlock(labelText, node) {
  const wrapper = document.createElement('div');
  const label = document.createElement('div');
  label.className = 'label';
  label.textContent = labelText;
  wrapper.appendChild(label);
  wrapper.appendChild(node);
  return wrapper;
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? '#b91c1c' : '#4b5563';
}

async function geocodeZip(zip) {
  const url = `https://nominatim.openstreetmap.org/search?format=json&postalcode=${encodeURIComponent(zip)}&countrycodes=us&limit=1&addressdetails=1`;
  const response = await fetch(url, { headers: { 'Accept-Language': 'en' } });
  if (!response.ok) throw new Error('ZIP lookup failed');
  const data = await response.json();
  if (!data.length) return null;
  const place = data[0];
  return {
    lat: parseFloat(place.lat),
    lon: parseFloat(place.lon),
    label: place.display_name
  };
}

async function fetchHospiceCenters(lat, lon, radiusKm) {
  const centers = [];
  const featured = featuredProviders
    .map((provider) => {
      const distance = haversineKm(lat, lon, provider.lat, provider.lon);
      const inRange = provider.serviceRadiusKm ? distance <= provider.serviceRadiusKm : true;
      return { ...provider, distance, source: 'featured', inRange };
    })
    .filter((p) => p.inRange);

  centers.push(...featured);
  // Merge directory providers within radius, using dynamic directory if loaded
  const directoryHits = getNearbyProviders(lat, lon, providerDirectory, radiusKm).map((p) => ({
    id: p.id,
    name: p.name,
    address: p.address,
    lat: p.lat,
    lon: p.lon,
    distance: p.distance,
    source: 'directory',
    email: p.email,
    phone: p.phone,
    website: p.website
  }));
  centers.push(...directoryHits);
  centers.sort((a, b) => (a.distance || 0) - (b.distance || 0));
  return centers;
}

function formatAddress(tags) {
  const parts = [tags['addr:housenumber'], tags['addr:street'], tags['addr:city'], tags['addr:state'], tags['addr:postcode']];
  const address = parts.filter(Boolean).join(', ');
  return address || tags['addr:full'] || tags['addr:place'];
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

function getNearbyProviders(lat, lon, providers, radiusKm) {
  return providers
    .map((p) => {
      const distance = haversineKm(lat, lon, p.lat, p.lon);
      return { ...p, distance };
    })
    .filter((p) => {
      const providerRadius = p.serviceRadiusKm || radiusKm;
      const effectiveRadius = Math.min(radiusKm, providerRadius);
      return p.distance <= effectiveRadius;
    });
}

async function loadRemoteProviders() {
  if (remoteProvidersLoaded) return;
  try {
    const res = await fetch('/api/providers');
    if (!res.ok) throw new Error('Failed to load providers');
    const remote = await res.json();
    if (Array.isArray(remote) && remote.length) {
      // Keep initial directory as defaults, append remote
      providerDirectory = [...providerDirectory, ...remote];
    }
    remoteProvidersLoaded = true;
  } catch (err) {
    console.warn('Could not load remote providers', err);
  }
}

async function notifyProviders(zip, providers, answers) {
  if (!providers || !providers.length) return 0;
  const toProviders = providers.filter((p) => !!p.email);
  if (!toProviders.length) return 0;
  try {
    const res = await fetch('/api/notify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        zip,
        answers,
        captchaToken: turnstileToken,
        providers: toProviders.map((p) => ({
          id: p.id,
          name: p.name,
          address: p.address,
          email: p.email,
          phone: p.phone || '',
          website: p.website || '',
          lat: p.lat,
          lon: p.lon
        }))
      })
    });
    if (!res.ok) throw new Error('Notify returned non-200');
    const data = await res.json();
    return data?.sent ?? toProviders.length;
  } catch (err) {
    console.warn('Provider notification failed', err);
    throw err;
  }
}
