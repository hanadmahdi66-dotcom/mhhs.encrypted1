/* ═══════════════════════════════════════════
   HANOVA · app.js
   ═══════════════════════════════════════════ */

// ── State ────────────────────────────────────
const state = {
  user: { name: '', email: '' },
  plan: 'free',        // 'free' | 'basic' | 'pro' | 'elite'
  planLabel: '$0',
  planAmount: '0',
  uploadsToday: 0,
  currentTab: 'photo', // 'photo' | 'text'
  history: [],
  photoData: null,     // base64 of uploaded photo
  photoFile: null,
};

const UPLOAD_LIMIT_FREE = 20;

// ── Helpers ───────────────────────────────────
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const target = document.getElementById(id);
  if (target) {
    target.classList.add('active');
    // Scroll to top
    target.scrollTop = 0;
  }
}

function toast(msg, duration = 2500) {
  const el = document.createElement('div');
  el.textContent = msg;
  Object.assign(el.style, {
    position: 'fixed', bottom: '80px', left: '50%',
    transform: 'translateX(-50%)',
    background: 'rgba(201,168,76,0.18)',
    border: '1px solid rgba(201,168,76,0.3)',
    backdropFilter: 'blur(12px)',
    color: '#e4c97e',
    padding: '0.65rem 1.4rem',
    borderRadius: '99px',
    fontSize: '0.82rem',
    letterSpacing: '0.06em',
    zIndex: '999',
    animation: 'fadeIn 0.25s both',
  });
  document.body.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ── Splash → Auth ─────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  showScreen('screen-splash');
  setTimeout(() => showScreen('screen-auth'), 6000);
});

// ── Auth ──────────────────────────────────────
function switchPanel(which) {
  document.querySelectorAll('.auth-panel').forEach(p => p.classList.remove('active'));
  document.getElementById(`panel-${which}`).classList.add('active');
}

function handleSignUp() {
  const name = document.getElementById('signup-name').value.trim();
  const email = document.getElementById('signup-email').value.trim();

  if (!name) { toast('Please enter your name'); return; }
  if (!email.match(/^[^\s@]+@gmail\.com$/i)) { toast('Please enter a valid Gmail address'); return; }

  state.user.name = name;
  state.user.email = email;
  showScreen('screen-plans');
}

function handleLogIn() {
  const email = document.getElementById('login-email').value.trim();
  const pass = document.getElementById('login-password').value;

  if (!email.match(/^[^\s@]+@gmail\.com$/i)) { toast('Please enter a valid Gmail address'); return; }
  if (!pass) { toast('Please enter your password'); return; }

  // Simulate login — pre-fill guest name if needed
  state.user.name = state.user.name || email.split('@')[0];
  state.user.email = email;
  goToHome();
}

// ── Plans ─────────────────────────────────────
function selectPlan(planKey, amount, label) {
  state.plan = planKey;
  state.planAmount = amount;
  state.planLabel = label;

  if (planKey === 'free') {
    // Skip payment, go straight to home
    goToHome();
    return;
  }

  // Build payment screen
  document.getElementById('pay-plan-name').textContent = label;
  document.getElementById('pay-amount').textContent = `$${amount}/month`;
  document.getElementById('zaad-code').textContent = `2200633718556*${amount}#`;

  showScreen('screen-payment');
}

function goToPlans() {
  showScreen('screen-plans');
}

// ── Payment ───────────────────────────────────
function copyZaadCode() {
  const code = document.getElementById('zaad-code').textContent;
  navigator.clipboard.writeText(code).then(() => {
    const btn = document.getElementById('copy-btn');
    btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
    toast('Code copied to clipboard');
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = code;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    toast('Code copied!');
  });
}

function confirmPayment() {
  // Show waiting popup
  const popup = document.getElementById('popup-waiting');
  popup.style.display = 'flex';

  // Restart the popup loader animation
  const fill = popup.querySelector('.popup-fill');
  fill.style.animation = 'none';
  fill.offsetHeight; // reflow
  fill.style.animation = 'load 6s linear forwards';

  // After 6 seconds, hide popup and go home
  setTimeout(() => {
    popup.style.display = 'none';
    goToHome();
  }, 6000);
}

// ── Home ──────────────────────────────────────
function goToHome() {
  // Update home UI
  const name = state.user.name || 'User';
  document.getElementById('home-greeting').textContent = `Hello, ${name}`;
  document.getElementById('home-plan-tag').textContent = planDisplayName(state.plan);
  document.getElementById('settings-name').textContent = name;
  document.getElementById('settings-email').textContent = state.user.email;
  document.getElementById('settings-plan-name').textContent = planDisplayName(state.plan);
  document.getElementById('settings-avatar').textContent = name.charAt(0).toUpperCase();

  // Limit notice for free
  updateLimitNotice();

  // Show/hide text tab for free users
  updateTextTab();

  // Reset photo preview
  state.photoData = null;
  state.photoFile = null;
  const preview = document.getElementById('photo-preview');
  preview.style.display = 'none';
  preview.src = '';

  // Hide response / loading
  document.getElementById('ai-response-wrap').style.display = 'none';
  document.getElementById('ai-loading').style.display = 'none';

  showScreen('screen-home');
}

function planDisplayName(key) {
  return { free: 'Free', basic: 'Basic', pro: 'Pro', elite: 'Elite' }[key] || 'Free';
}

function updateLimitNotice() {
  const el = document.getElementById('home-limit-notice');
  if (state.plan === 'free') {
    const left = UPLOAD_LIMIT_FREE - state.uploadsToday;
    el.textContent = `Free plan · ${left} uploads remaining today`;
    el.style.display = 'block';
  } else {
    el.textContent = '';
    el.style.display = 'none';
  }
}

function updateTextTab() {
  const isPremium = state.plan !== 'free';
  const textLockedMsg = document.getElementById('text-locked-msg');
  const textInputWrap = document.getElementById('text-input-wrap');

  if (isPremium) {
    textLockedMsg.style.display = 'none';
    textInputWrap.style.display = 'block';
  } else {
    textLockedMsg.style.display = 'flex';
    textInputWrap.style.display = 'none';
  }
}

// ── AI Tabs ───────────────────────────────────
function switchTab(tab) {
  state.currentTab = tab;
  document.querySelectorAll('.ai-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.ai-panel').forEach(p => p.classList.remove('active'));

  document.getElementById(`tab-${tab}`).classList.add('active');
  document.getElementById(`ai-${tab}-panel`).classList.add('active');

  // Hide previous response
  document.getElementById('ai-response-wrap').style.display = 'none';
}

// ── Photo Upload ──────────────────────────────
function handlePhotoUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  if (state.plan === 'free' && state.uploadsToday >= UPLOAD_LIMIT_FREE) {
    toast('Daily upload limit reached. Upgrade to continue.');
    return;
  }

  state.photoFile = file;
  const reader = new FileReader();
  reader.onload = (e) => {
    state.photoData = e.target.result; // data URL
    const preview = document.getElementById('photo-preview');
    preview.src = state.photoData;
    preview.style.display = 'block';
  };
  reader.readAsDataURL(file);
}

// ── AI Submit ─────────────────────────────────
async function submitToAI() {
  const tab = state.currentTab;

  if (tab === 'text' && state.plan === 'free') {
    toast('Upgrade to a paid plan to use text input.');
    return;
  }

  if (tab === 'photo') {
    if (!state.photoData) { toast('Please upload a photo first.'); return; }
    if (state.plan === 'free' && state.uploadsToday >= UPLOAD_LIMIT_FREE) {
      toast('Daily limit reached. Upgrade for more uploads.'); return;
    }
  }

  if (tab === 'text') {
    const txt = document.getElementById('text-input').value.trim();
    if (!txt) { toast('Please enter some text first.'); return; }
  }

  // Show loading
  document.getElementById('ai-loading').style.display = 'flex';
  document.getElementById('ai-response-wrap').style.display = 'none';
  document.getElementById('ai-submit-btn').disabled = true;

  try {
    let responseText = '';

    if (tab === 'photo') {
      responseText = await callClaudeWithPhoto();
      state.uploadsToday++;
      updateLimitNotice();
    } else {
      responseText = await callClaudeWithText();
    }

    // Save to history
    state.history.unshift({
      type: tab === 'photo' ? 'Photo' : 'Text',
      response: responseText,
      time: new Date().toLocaleString(),
    });
    renderHistory();

    // Show response
    document.getElementById('ai-response-text').textContent = responseText;
    document.getElementById('ai-response-wrap').style.display = 'block';
    document.getElementById('ai-response-wrap').style.animation = 'none';
    document.getElementById('ai-response-wrap').offsetHeight;
    document.getElementById('ai-response-wrap').style.animation = 'fadeUp 0.5s both';

    // Scroll to response
    setTimeout(() => {
      document.getElementById('ai-response-wrap').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 100);

  } catch (err) {
    console.error(err);
    toast('Something went wrong. Please try again.');
  } finally {
    document.getElementById('ai-loading').style.display = 'none';
    document.getElementById('ai-submit-btn').disabled = false;
  }
}

// ── Claude API Calls ──────────────────────────
async function callClaudeWithPhoto() {
  // Convert data URL to base64
  const base64 = state.photoData.split(',')[1];
  const mediaType = state.photoData.match(/data:([^;]+)/)[1];

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: [
          {
            type: 'image',
            source: { type: 'base64', media_type: mediaType, data: base64 }
          },
          {
            type: 'text',
            text: 'You are Hanova, a luxury AI assistant with an eloquent, sophisticated voice. Describe and analyse this image in a thoughtful, beautifully written response. Be insightful, poetic, and precise. Keep it to 2–4 sentences.'
          }
        ]
      }]
    })
  });

  const data = await response.json();
  if (data.error) throw new Error(data.error.message);
  return data.content.map(c => c.text || '').filter(Boolean).join('\n');
}

async function callClaudeWithText() {
  const text = document.getElementById('text-input').value.trim();

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: `You are Hanova, a luxury AI assistant with an eloquent, sophisticated voice. Answer the following with beauty, clarity, and insight — in 2–4 sentences:\n\n${text}`
      }]
    })
  });

  const data = await response.json();
  if (data.error) throw new Error(data.error.message);
  return data.content.map(c => c.text || '').filter(Boolean).join('\n');
}

// ── History ───────────────────────────────────
function renderHistory() {
  const list = document.getElementById('history-list');
  if (state.history.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📜</div>
        <p>No history yet.<br />Your AI conversations will appear here.</p>
      </div>`;
    return;
  }
  list.innerHTML = state.history.map(item => `
    <div class="history-item">
      <div class="history-item-type">${item.type} Upload</div>
      <div class="history-item-resp">${escHtml(item.response)}</div>
      <div class="history-item-time">${item.time}</div>
    </div>
  `).join('');
}

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

// ── Settings / Popups ─────────────────────────
function showCredits() {
  document.getElementById('popup-credits').style.display = 'flex';
}
function closeCredits(e) {
  if (!e || e.target.id === 'popup-credits') {
    document.getElementById('popup-credits').style.display = 'none';
  }
}

function showPrivacy() {
  document.getElementById('popup-privacy').style.display = 'flex';
}
function showTerms() {
  document.getElementById('popup-terms').style.display = 'flex';
}
function closePopup(id, e) {
  if (!e || e.target.id === id) {
    document.getElementById(id).style.display = 'none';
  }
}

function logOut() {
  if (!confirm('Are you sure you want to log out?')) return;
  // Reset state
  state.user = { name: '', email: '' };
  state.plan = 'free';
  state.uploadsToday = 0;
  state.history = [];
  state.photoData = null;
  // Clear inputs
  document.getElementById('signup-name').value = '';
  document.getElementById('signup-email').value = '';
  document.getElementById('login-email').value = '';
  document.getElementById('login-password').value = '';
  switchPanel('signup');
  showScreen('screen-auth');
}

// ── Bottom nav helper ─────────────────────────
function setNav(btn, target) {
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (target === 'home-main') {
    showScreen('screen-home');
  }
}

// ── Keyboard dismiss ──────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    ['popup-waiting','popup-credits','popup-privacy','popup-terms'].forEach(id => {
      const el = document.getElementById(id);
      if (el && el.style.display !== 'none') el.style.display = 'none';
    });
  }
});
