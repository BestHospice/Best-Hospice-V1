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
    id: 'firstName',
    title: 'What is your first name?',
    desc: 'So providers know who to address',
    type: 'text'
  },
  {
    id: 'lastName',
    title: 'What is your last name?',
    desc: 'Helps providers personalize their outreach',
    type: 'text'
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
    times: ['Morning', 'Afternoon', 'Night', 'All day']
  },
  {
    id: 'services',
    title: 'What do you need help with?',
    desc: 'Select all that apply — this helps match you with the right hospice',
    type: 'checklist',
    groups: [
      {
        title: 'Pain & Symptom Management',
        subtitle: 'Core hospice nursing services',
        items: [
          'Pain control and medication management',
          'Shortness of breath / breathing support',
          'Anxiety or agitation management',
          'Nausea or vomiting control',
          'Terminal restlessness or confusion',
          'Fatigue and weakness management',
          'Difficulty swallowing'
        ]
      },
      {
        title: 'Medication Support',
        subtitle: 'Common reason families seek hospice',
        items: [
          'Medication administration',
          'Medication education for caregivers',
          'Comfort medication kit (home hospice)',
          'Medication delivery coordination',
          'Reducing or stopping non-essential medications'
        ]
      },
      {
        title: 'Personal & Daily Care Support',
        subtitle: 'Often coordinated with hospice aides',
        items: [
          'Bathing and hygiene assistance',
          'Repositioning / pressure sore prevention',
          'Incontinence care',
          'Catheter care',
          'Feeding assistance',
          'Wound or skin care'
        ]
      },
      {
        title: 'Medical Equipment & Supplies',
        subtitle: 'Logistics matter to families',
        items: [
          'Hospital bed delivery',
          'Oxygen support',
          'Wheelchair or walker',
          'Bedside commode',
          'Medical supplies provided (dressings, gloves, etc.)'
        ]
      },
      {
        title: 'Emotional & Psychological Support',
        subtitle: 'High trust-building category',
        items: [
          'Emotional support for patient',
          'Emotional support for family',
          'Anxiety or fear counseling',
          'End-of-life emotional guidance'
        ]
      },
      {
        title: 'Family & Caregiver Education',
        subtitle: 'Critical for at-home hospice',
        items: [
          'How to give medications safely',
          'What to expect as illness progresses',
          'Signs of active dying',
          'How to care for patient at home',
          'What to do at time of death'
        ]
      },
      {
        title: 'End-of-Life & Active Dying Support',
        subtitle: 'Often searched late in the decision process',
        items: [
          'Intensive symptom management near end of life',
          'Bedside support during active dying',
          'Guidance through final hours or days',
          'Death pronouncement coordination'
        ]
      },
      {
        title: 'Care Coordination & Advocacy',
        subtitle: 'Differentiates high-quality hospices',
        items: [
          'Coordination with hospice physician',
          'Coordination with pharmacy',
          'Coordination with social worker',
          'Care plan management',
          'Advance directive support'
        ]
      },
      {
        title: 'Spiritual & Cultural Support (Optional)',
        subtitle: 'Important for many families',
        items: [
          'Chaplain or spiritual care available',
          'Faith-based hospice program',
          'Cultural or language-specific support'
        ]
      },
      {
        title: 'Bereavement & After-Death Support',
        subtitle: 'Often overlooked but highly valued',
        items: [
          'Immediate family support after death',
          'Funeral home coordination',
          'Bereavement counseling',
          'Grief support groups'
        ]
      }
    ]
  },
  {
    id: 'moreDetails',
    title: 'If you have more specific needs or want to allow us to decide what care is best, type your situation below',
    desc: 'Optional: share anything unique about your situation',
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
          showQuestionnaire();
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
  if (!answer || (Array.isArray(answer) && answer.length === 0)) return;
  userResponses.answers[q.id] = answer;
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
      const badge = center.source === 'featured' ? '<span class="badge">Featured</span>' : '';
      const contactLines = [];
      if (center.phone) contactLines.push(center.phone);
      if (center.website) contactLines.push(`<a href="${center.website}" target="_blank" rel="noopener">Website</a>`);
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
          ${center.website ? `<span><a href="${center.website}" target="_blank" rel="noopener">Website</a></span>` : ''}
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
  addItem('First name', answers.firstName || 'Not provided');
  addItem('Last name', answers.lastName || 'Not provided');
  addItem('Who needs care', prettyRelationship(answers.relationship));
  const freqDays = answers.frequency?.days?.join(', ') || 'Not specified';
  const freqTimes = answers.frequency?.times?.join(', ') || 'Not specified';
  addItem('Care days', freqDays);
  addItem('Care times', freqTimes);
  addItem('Selected services', answers.services?.join('; ') || 'Not specified');
  addItem('More details', answers.moreDetails || 'Not provided');
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
    `Client name: ${(answers.firstName || '') + ' ' + (answers.lastName || '')}`.trim(),
    `Who needs care: ${prettyRelationship(answers.relationship)}`,
    `Care days: ${freqDays}`,
    `Care times: ${freqTimes}`,
    `Services: ${answers.services?.join('; ') || 'Not specified'}`,
    `Client contact email: ${answers.contactEmail || 'Not provided'}`,
    `Client phone: ${answers.contactPhone || 'Not provided'}`,
    `More details: ${answers.moreDetails || 'Not provided'}`,
    '',
    'Nearby hospice providers:',
    ...centers.slice(0, 5).map((c) => `- ${c.name}${c.address ? ' — ' + c.address : ''}`),
    '',
    'Providers to notify:',
    ...(nearbyProviders.length
      ? nearbyProviders.map((p) => `- ${p.name} (${p.email})`)
      : ['- None within range'])
  ];
  if (nearbyProviders.length) {
    const toList = nearbyProviders.map((p) => p.email).join(',');
    const mailto = `mailto:${encodeURIComponent(toList)}?subject=${subject}&body=${encodeURIComponent(bodyLines.join('\n'))}`;
    summaryEmail.href = mailto;
    summaryEmail.textContent = 'Email this summary';
    summaryEmail.classList.remove('disabled');
  } else {
    summaryEmail.href = '#';
    summaryEmail.textContent = 'No providers in range to email';
    summaryEmail.classList.add('disabled');
  }
}

function prettyRelationship(value) {
  if (value === 'me') return 'Me';
  if (value === 'loved-one') return 'Loved one';
  if (value === 'other') return 'Other';
  return 'Not specified';
}

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
  const radiusMeters = radiusKm * 1000;
  const query = `
    [out:json][timeout:25];
    (
      nwr["healthcare"="hospice"](around:${radiusMeters},${lat},${lon});
      nwr["amenity"="hospice"](around:${radiusMeters},${lat},${lon});
    );
    out center tags;
  `;

  const response = await fetch('https://overpass-api.de/api/interpreter', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: query
  });

  if (!response.ok) throw new Error('Overpass query failed');
  const data = await response.json();

  const centers = [];
  for (const el of data.elements || []) {
    const coords = el.lat && el.lon ? { lat: el.lat, lon: el.lon } : el.center;
    if (!coords) continue;
    const name = el.tags?.name || 'Unnamed hospice center';
    const address = formatAddress(el.tags || {});
    const distance = haversineKm(lat, lon, coords.lat, coords.lon);
    centers.push({ name, address, lat: coords.lat, lon: coords.lon, distance, source: 'osm' });
  }

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
