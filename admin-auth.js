window.adminAuth = (() => {
  async function getSession() {
    const res = await fetch('/api/admin/session', { credentials: 'same-origin' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Unauthorized');
    return data;
  }

  async function login(email, password) {
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Login failed');
    return data;
  }

  async function loginAndConfirmSession(email, password) {
    await login(email, password);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        return await getSession();
      } catch (_err) {
        await new Promise((resolve) => setTimeout(resolve, 150));
      }
    }
    throw new Error('Login succeeded, but the admin session was not ready. Please try again.');
  }

  async function logout() {
    await fetch('/api/admin/logout', {
      method: 'POST',
      credentials: 'same-origin'
    }).catch(() => {});
  }

  async function requireSession() {
    try {
      return await getSession();
    } catch (_err) {
      const next = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.href = `/admin.html?next=${next}`;
      throw _err;
    }
  }

  return { getSession, login, loginAndConfirmSession, logout, requireSession };
})();
