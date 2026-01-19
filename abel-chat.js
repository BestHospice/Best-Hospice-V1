(() => {
  const btnStyles = `
    position:fixed; right:18px; bottom:18px; z-index:9999;
    background:linear-gradient(135deg,#2563eb,#1d4ed8); color:#fff;
    border:none; border-radius:999px; padding:10px 14px; font-weight:700;
    box-shadow:0 10px 20px rgba(37,99,235,0.35); cursor:pointer;
  `;
    const panelStyles = `
    position:fixed; right:18px; bottom:70px; z-index:9999; width:320px;
    background:#fff; border:1px solid #e5e7eb; border-radius:14px;
    box-shadow:0 18px 38px rgba(15,23,42,0.25); display:flex; flex-direction:column; overflow:hidden;
  `;
  const headerStyles = `
    padding:10px 12px; background:#0f172a; color:#fff; font-weight:800; display:flex; justify-content:space-between; align-items:center;
  `;
  const bodyStyles = `padding:10px; display:flex; flex-direction:column; gap:8px; max-height:340px; overflow:auto;`;
  const inputStyles = `width:100%; padding:10px; border:1px solid #d1d5db; border-radius:10px;`;

  const bubble = (text, from) => {
    const div = document.createElement('div');
    div.style.cssText = `padding:10px; border-radius:10px; max-width:90%; font-size:14px; line-height:1.4; ${from === 'agent' ? 'background:#eef2ff; color:#1f2937;' : 'background:#f8fafc; color:#111827; align-self:flex-end;'} `;
    div.innerHTML = text;
    return div;
  };

  function getMode() {
    const token = localStorage.getItem('provider_jwt');
    return token ? 'provider' : 'client';
  }

  async function chat(message, mode, token) {
    const payload = { message, mode };
    const headers = { 'Content-Type': 'application/json' };
    if (mode === 'provider' && token) headers['Authorization'] = 'Bearer ' + token;
    // best effort to include turnstile token if you later wire one
    payload.turnstileToken = null;
    const res = await fetch('/api/ai/chat', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  function init() {
    if (document.getElementById('abel-chat-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'abel-chat-btn';
    btn.style.cssText = btnStyles;
    btn.textContent = 'Abel • Need help?';

    const panel = document.createElement('div');
    panel.id = 'abel-chat-panel';
    panel.style.cssText = panelStyles;
    panel.style.display = 'none';

    const header = document.createElement('div');
    header.style.cssText = headerStyles;
    header.innerHTML = `
      <span>Abel (AI)</span>
      <div style="display:flex; gap:6px; align-items:center;">
        <button id="abel-send-top" style="background:#38bdf8; color:#0f172a; border:none; padding:6px 10px; border-radius:8px; font-weight:700; cursor:pointer;">Send</button>
        <button id="abel-close" style="background:transparent; color:#fff; border:none; font-size:16px; cursor:pointer;">×</button>
      </div>
    `;

    const body = document.createElement('div');
    body.id = 'abel-body';
    body.style.cssText = bodyStyles;
    body.appendChild(bubble('Hi, I am Abel. Are you a Client/Family member or a Provider? I can help with questions and site navigation.', 'agent'));

    const inputRow = document.createElement('div');
    inputRow.style.cssText = 'display:flex; gap:8px; align-items:flex-end;';
    const input = document.createElement('textarea');
    input.id = 'abel-input';
    input.rows = 2;
    input.style.cssText = `${inputStyles} flex:1;`;
    input.placeholder = 'Type your message...';
    inputRow.appendChild(input);

    const wrapper = document.createElement('div');
    wrapper.style.cssText = 'display:flex; flex-direction:column; gap:8px; padding:10px;';
    wrapper.appendChild(body);
    wrapper.appendChild(inputRow);

    panel.appendChild(header);
    panel.appendChild(wrapper);

    document.body.appendChild(btn);
    document.body.appendChild(panel);

    btn.addEventListener('click', () => {
      panel.style.display = panel.style.display === 'none' ? 'flex' : 'none';
    });
    header.querySelector('#abel-close').addEventListener('click', () => panel.style.display = 'none');

    const sendAction = async () => {
      const msg = input.value.trim();
      if (!msg) return;
      const mode = getMode();
      const token = localStorage.getItem('provider_jwt');
      body.appendChild(bubble(msg, 'user'));
      input.value = '';
      body.scrollTop = body.scrollHeight;
      try {
        const resp = await chat(msg, mode, token);
        if (resp.reply) body.appendChild(bubble(resp.reply, 'agent'));
        if (resp.navigateTo) {
          const nav = document.createElement('div');
          nav.style.cssText = 'margin-top:6px;';
          const linkBtn = document.createElement('button');
          linkBtn.style.cssText = `${btnStyles} padding:8px 10px; box-shadow:none;`;
          linkBtn.textContent = 'Go to ' + resp.navigateTo;
          linkBtn.addEventListener('click', () => { window.location.href = resp.navigateTo; });
          nav.appendChild(linkBtn);
          body.appendChild(nav);
        }
      } catch (err) {
        body.appendChild(bubble(err.message, 'agent'));
      }
      body.scrollTop = body.scrollHeight;
    };

    header.querySelector('#abel-send-top').addEventListener('click', sendAction);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendAction();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
