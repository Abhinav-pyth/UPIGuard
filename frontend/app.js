/* ─── UPIGuard Frontend JS v2 ──────────────────────────────────── */

const API_BASE = '';

// ── Token Storage (sessionStorage — cleared on tab close) ────────
const TokenStore = {
  get:    ()      => sessionStorage.getItem('upiguard_token'),
  set:    (t)     => sessionStorage.setItem('upiguard_token', t),
  clear:  ()      => sessionStorage.removeItem('upiguard_token'),
};

// ── Particle Canvas ─────────────────────────────────────────────
(function initParticles() {
  const canvas = document.getElementById('particle-canvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles;

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  function createParticles() {
    const count = Math.floor((W * H) / 18000);
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.3, alpha: Math.random() * 0.4 + 0.1,
    }));
  }
  function draw() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(167, 139, 250, ${p.alpha})`;
      ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  resize(); createParticles(); draw();
  window.addEventListener('resize', () => { resize(); createParticles(); });
})();

// ── Security: escape HTML ────────────────────────────────────────
function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

// ── UPI Validation ───────────────────────────────────────────────
const UPI_REGEX = /^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$/;
function validateUPI(value) {
  const v = value.trim();
  if (!v) return 'Please enter your UPI ID.';
  if (!UPI_REGEX.test(v)) return 'Invalid format. Use username@bankhandle — e.g. john@oksbi';
  return null;
}

// ── API Helper ───────────────────────────────────────────────────
async function apiPost(path, body, withAuth = false) {
  const headers = { 'Content-Type': 'application/json' };
  if (withAuth) {
    const token = TokenStore.get();
    if (!token) throw new Error('Not authenticated. Please login.');
    headers['Authorization'] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = data?.detail;
    const msg = Array.isArray(detail)
      ? detail.map(d => d.msg).join('; ')
      : typeof detail === 'string' ? detail : `Error ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

async function apiGet(path) {
  const token = TokenStore.get();
  if (!token) throw new Error('Not authenticated.');
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.detail || `Error ${res.status}`);
  return data;
}

// ── Auth State Management ────────────────────────────────────────
const headerGuest  = document.getElementById('header-guest');
const headerUser   = document.getElementById('header-user');
const userEmailEl  = document.getElementById('user-email-display');
const checkerCard  = document.getElementById('checker-card');
const authNotice   = document.getElementById('auth-required-notice');

let _currentEmail = null;

function applyAuthState(email) {
  _currentEmail = email;
  if (email) {
    headerGuest.hidden = true;
    headerUser.hidden  = false;
    userEmailEl.textContent = email;
    checkerCard.hidden  = false;
    authNotice.hidden   = true;
  } else {
    headerGuest.hidden = false;
    headerUser.hidden  = true;
    checkerCard.hidden  = true;
    authNotice.hidden   = false;
  }
}

// ── Modal helpers ────────────────────────────────────────────────
function openModal(overlayId) {
  document.getElementById(overlayId).hidden = false;
  document.body.classList.add('modal-open');
}
function closeModal(overlayId) {
  document.getElementById(overlayId).hidden = true;
  document.body.classList.remove('modal-open');
}

// ── Auth Modal ───────────────────────────────────────────────────
const authOverlay  = document.getElementById('auth-overlay');
const tabLogin     = document.getElementById('tab-login');
const tabRegister  = document.getElementById('tab-register');
const panelLogin   = document.getElementById('panel-login');
const panelRegister= document.getElementById('panel-register');

function switchTab(tab) {
  const isLogin = tab === 'login';
  tabLogin.classList.toggle('active', isLogin);
  tabRegister.classList.toggle('active', !isLogin);
  tabLogin.setAttribute('aria-selected', isLogin);
  tabRegister.setAttribute('aria-selected', !isLogin);
  panelLogin.hidden    = !isLogin;
  panelRegister.hidden = isLogin;
}

document.getElementById('open-auth-btn').addEventListener('click', () => openModal('auth-overlay'));
document.getElementById('notice-login-btn').addEventListener('click', () => openModal('auth-overlay'));
document.getElementById('auth-close-btn').addEventListener('click', () => closeModal('auth-overlay'));
authOverlay.addEventListener('click', e => { if (e.target === authOverlay) closeModal('auth-overlay'); });

tabLogin.addEventListener('click',    () => switchTab('login'));
tabRegister.addEventListener('click', () => switchTab('register'));
document.getElementById('goto-register').addEventListener('click', () => switchTab('register'));
document.getElementById('goto-login').addEventListener('click',    () => switchTab('login'));


// ── Register ─────────────────────────────────────────────────────
const registerForm = document.getElementById('register-form');
const registerError = document.getElementById('register-error');

registerForm.addEventListener('submit', async e => {
  e.preventDefault();
  registerError.textContent = '';
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const consent  = document.getElementById('consent-checkbox').checked;

  if (!consent) { registerError.textContent = 'Please accept the consent terms.'; return; }

  const btn = document.getElementById('register-btn');
  btn.disabled = true; btn.textContent = 'Creating…';
  try {
    const data = await apiPost('/api/register', { email, password, consent_given: consent });
    TokenStore.set(data.access_token);
    closeModal('auth-overlay');
    applyAuthState(email);
  } catch (err) {
    registerError.textContent = err.message;
  } finally {
    btn.disabled = false; btn.textContent = 'Create Account';
  }
});

// ── Login ─────────────────────────────────────────────────────────
const loginForm  = document.getElementById('login-form');
const loginError = document.getElementById('login-error');

loginForm.addEventListener('submit', async e => {
  e.preventDefault();
  loginError.textContent = '';
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  const btn = document.getElementById('login-btn');
  btn.disabled = true; btn.textContent = 'Logging in…';
  try {
    const data = await apiPost('/api/login', { email, password });
    TokenStore.set(data.access_token);
    closeModal('auth-overlay');
    applyAuthState(email);
  } catch (err) {
    loginError.textContent = err.message;
  } finally {
    btn.disabled = false; btn.textContent = 'Login';
  }
});


// ── Logout ───────────────────────────────────────────────────────
document.getElementById('logout-btn').addEventListener('click', () => {
  TokenStore.clear();
  applyAuthState(null);
  document.getElementById('results-section').hidden = true;
  document.getElementById('remediation-section').hidden = true;
  hideDashboard();
});

// ── Dashboard ────────────────────────────────────────────────────
const dashboardSection = document.getElementById('dashboard-section');
const checkerSection   = document.getElementById('checker-section');
const statsBar         = document.getElementById('stats-bar');

function hideDashboard() {
  dashboardSection.hidden = true;
  checkerSection.hidden   = false;
  statsBar.hidden         = false;
}

document.getElementById('show-dashboard-btn').addEventListener('click', async () => {
  try {
    const data = await apiGet('/api/dashboard');
    renderDashboard(data);
    dashboardSection.hidden = false;
    checkerSection.hidden   = true;
    statsBar.hidden         = true;
    document.getElementById('results-section').hidden = true;
    document.getElementById('remediation-section').hidden = true;
    dashboardSection.scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    alert('Could not load dashboard: ' + err.message);
  }
});

document.getElementById('back-to-checker-btn').addEventListener('click', hideDashboard);

function renderDashboard(data) {
  const statsEl   = document.getElementById('dashboard-stats');
  const historyEl = document.getElementById('dashboard-history');

  const compromisedCount = data.checks.filter(c => c.is_compromised).length;

  statsEl.innerHTML = `
    <div class="dash-stat-card glass-card">
      <div class="dash-stat-icon">🔍</div>
      <div class="dash-stat-num">${data.total_checks}</div>
      <div class="dash-stat-label">Total Checks</div>
    </div>
    <div class="dash-stat-card glass-card ${compromisedCount > 0 ? 'danger' : 'safe'}">
      <div class="dash-stat-icon">${compromisedCount > 0 ? '⚠️' : '✅'}</div>
      <div class="dash-stat-num">${compromisedCount}</div>
      <div class="dash-stat-label">Breaches Found</div>
    </div>
    <div class="dash-stat-card glass-card">
      <div class="dash-stat-icon">📅</div>
      <div class="dash-stat-num dash-stat-date">${new Date(data.member_since).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</div>
      <div class="dash-stat-label">Member Since</div>
    </div>
  `;

  if (!data.checks.length) {
    historyEl.innerHTML = `<div class="dash-empty">No checks yet. Go back and check a UPI ID!</div>`;
    return;
  }

  historyEl.innerHTML = `
    <h3 class="dash-history-title">Check History</h3>
    <div class="dash-history-list">
      ${data.checks.map(c => `
        <div class="dash-history-row glass-card ${c.is_compromised ? 'row-danger' : 'row-safe'}">
          <div class="row-icon">${c.is_compromised ? '⚠️' : '✅'}</div>
          <div class="row-body">
            <div class="row-upi"><code>${escapeHtml(c.upi_masked)}</code></div>
            <div class="row-meta">
              ${c.is_compromised ? `<span class="row-breach-badge">${c.breach_count} breach${c.breach_count > 1 ? 'es' : ''}</span>` : '<span class="row-safe-badge">Clean</span>'}
              · ${new Date(c.checked_at).toLocaleString('en-IN')}
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

// ── Checker Form ─────────────────────────────────────────────────
const form            = document.getElementById('checker-form');
const upiInput        = document.getElementById('upi-input');
const checkBtn        = document.getElementById('check-btn');
const inputGroup      = document.getElementById('input-group');
const inputError      = document.getElementById('input-error');
const resultsSection  = document.getElementById('results-section');
const remediationSection = document.getElementById('remediation-section');

function setLoading(loading) {
  checkBtn.disabled = loading;
  checkBtn.classList.toggle('loading', loading);
}
function showError(msg) {
  inputError.textContent = msg;
  inputError.classList.add('visible');
  inputGroup.classList.add('has-error');
}
function clearError() {
  inputError.textContent = '';
  inputError.classList.remove('visible');
  inputGroup.classList.remove('has-error');
}

const SEVERITY_EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
function formatSeverity(s) {
  return (SEVERITY_EMOJI[s] ?? '⚪') + ' ' + s.charAt(0).toUpperCase() + s.slice(1);
}
function formatDate(dateStr) {
  try { return new Date(dateStr).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' }); }
  catch { return dateStr; }
}
function formatFieldName(f) {
  return f.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function renderResults(data) {
  const { upi_id, is_compromised, breach_count, breaches, checked_at, message } = data;
  const bannerClass = is_compromised ? 'breached' : 'safe';
  const bannerIcon  = is_compromised ? '⚠️' : '✅';
  const bannerTitle = is_compromised
    ? `Found in ${breach_count} breach${breach_count > 1 ? 'es' : ''}`
    : 'No breaches detected';

  let html = `
    <div class="status-banner ${bannerClass}" role="status" aria-label="Check result: ${bannerTitle}">
      <div class="status-icon-wrap" aria-hidden="true">${bannerIcon}</div>
      <div class="status-body">
        <div class="status-title">${bannerTitle}</div>
        <div class="status-upi-id">UPI ID: <strong>${escapeHtml(upi_id)}</strong></div>
        <div class="status-message">${escapeHtml(message)}</div>
        <div class="status-meta">Checked at ${new Date(checked_at).toLocaleTimeString('en-IN')} · Results saved to your history</div>
      </div>
    </div>
  `;

  if (is_compromised && breaches.length) {
    html += `<div class="breach-list" role="list" aria-label="Breach details">`;
    breaches.forEach(b => {
      html += `
        <article class="breach-card glass-card" role="listitem" aria-label="Breach from ${escapeHtml(b.source)}">
          <div class="breach-card-header">
            <div class="breach-source">${escapeHtml(b.source)}</div>
            <div class="severity-badge ${b.severity}" aria-label="Severity: ${b.severity}">${formatSeverity(b.severity)}</div>
          </div>
          <div class="breach-date">📅 Breach date: <strong>${formatDate(b.breach_date)}</strong></div>
          <div class="breach-desc">${escapeHtml(b.description)}</div>
          <div class="exposed-tags" aria-label="Exposed fields">
            ${b.records_exposed.map(f => `<span class="exposed-tag" title="Exposed field">${escapeHtml(formatFieldName(f))}</span>`).join('')}
          </div>
        </article>
      `;
    });
    html += `</div>`;
  }

  resultsSection.innerHTML = html;
  resultsSection.hidden = false;
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  remediationSection.hidden = !is_compromised;
}

form.addEventListener('submit', async e => {
  e.preventDefault();
  clearError();
  const raw = upiInput.value.trim();
  const validationError = validateUPI(raw);
  if (validationError) { showError(validationError); upiInput.focus(); return; }

  if (!TokenStore.get()) { openModal('auth-overlay'); return; }

  setLoading(true);
  resultsSection.hidden = true;
  remediationSection.hidden = true;

  try {
    const data = await apiPost('/api/check', { upi_id: raw }, true);
    renderResults(data);
  } catch (err) {
    if (err.message.includes('authenticated') || err.message.includes('401')) {
      TokenStore.clear();
      applyAuthState(null);
      openModal('auth-overlay');
    } else {
      showError(err.message);
    }
  } finally {
    setLoading(false);
  }
});

// Live validation
let debounceTimer;
upiInput.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    const err = validateUPI(upiInput.value);
    if (upiInput.value && err) showError(err); else clearError();
  }, 400);
});

// ── Load stats ───────────────────────────────────────────────────
(async function loadStats() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const data = await res.json();
    const el = document.getElementById('stat-records');
    if (el && data.breach_records_loaded) el.textContent = data.breach_records_loaded + '+';
  } catch { /* silent */ }
})();

// ── Init ─────────────────────────────────────────────────────────
(function init() {
  // Restore auth state if token present in sessionStorage
  const token = TokenStore.get();
  if (token) {
    // Decode email from JWT payload (base64 — no verification, just display)
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (payload?.email && payload?.exp * 1000 > Date.now()) {
        applyAuthState(payload.email);
        return;
      }
    } catch { /* fall through */ }
    TokenStore.clear();
  }
  applyAuthState(null);
})();
