/* teljesen feljavított kliens-oldali auth (demo) */
/* használ: localStorage: pr_users (array), pr_user (session) */
/* jelszó biztonságosabb kezelése: salt + SHA-256 (demó; éles környezethez backend kell) */

const AUTH_KEY = 'pr_user';
const USERS_KEY = 'pr_users';

/* util: hex konverzió */
function bufToHex(buffer){
  return Array.from(new Uint8Array(buffer)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function strToBuf(str){ return new TextEncoder().encode(str); }

/* generál egy véletlen salt-ot (base64) */
function genSalt(len = 16){
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b));
}

/* hash: SHA-256 of (salt + password) -> hex */
async function hashPassword(password, salt){
  const data = strToBuf(salt + password);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bufToHex(digest);
}

/* injected modal markup, ha nincs jelen a DOM-ban */
function ensureAuthModal(){
  if(document.getElementById('authModal')) return;
  const html = `
  <div id="authModal" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="authTitle">
    <div class="modal-panel">
      <button class="modal-close" id="modalClose" aria-label="Bezárás">✕</button>
      <h2 id="authTitle">Bejelentkezés</h2>

      <form id="loginForm" class="auth-form">
        <label>Email
          <input type="email" id="loginEmail" required autocomplete="username">
        </label>
        <label>Jelszó
          <input type="password" id="loginPassword" required autocomplete="current-password">
        </label>
        <div class="form-actions">
          <button type="submit" class="btn">Bejelentkezés</button>
          <button type="button" id="showRegister" class="btn ghost">Regisztráció</button>
        </div>
      </form>

      <form id="registerForm" class="auth-form hidden">
        <label>Teljes név
          <input type="text" id="regName" required autocomplete="name">
        </label>
        <label>Email
          <input type="email" id="regEmail" required autocomplete="email">
        </label>
        <label>Jelszó
          <input type="password" id="regPassword" required minlength="6" autocomplete="new-password">
        </label>
        <div class="form-actions">
          <button type="submit" class="btn">Regisztrálok</button>
          <button type="button" id="showLogin" class="btn ghost">Vissza</button>
        </div>
      </form>
    </div>
  </div>`;
  document.body.insertAdjacentHTML('beforeend', html);
}

/* UI inicializálás (async azért, mert hash függvény async) */
async function initUI(){
  ensureAuthModal();

  const loginBtn = document.getElementById('loginBtn');
  const ctaLogin = document.getElementById('ctaLogin');
  const ctaExplore = document.getElementById('ctaExplore');
  const mobileToggle = document.getElementById('mobileToggle');
  const nav = document.querySelector('.main-nav');

  loginBtn?.addEventListener('click', ()=> showAuthModal('login'));
  ctaLogin?.addEventListener('click', ()=> showAuthModal('login'));
  ctaExplore?.addEventListener('click', ()=> location.href='fandom.html');
  if(mobileToggle && nav) mobileToggle.addEventListener('click', ()=> nav.classList.toggle('open'));

  document.getElementById('modalClose')?.addEventListener('click', hideAuthModal);
  document.getElementById('showRegister')?.addEventListener('click', ()=> toggleAuthForms(true));
  document.getElementById('showLogin')?.addEventListener('click', ()=> toggleAuthForms(false));

  document.getElementById('loginForm')?.addEventListener('submit', async (e)=> { e.preventDefault(); await handleLogin(e); });
  document.getElementById('registerForm')?.addEventListener('submit', async (e)=> { e.preventDefault(); await handleRegister(e); });

  document.getElementById('logoutBtn')?.addEventListener('click', logout);

  updateAuthUI();
  enforcePageProtection();
}

/* modal show/hide */
function showAuthModal(mode='login'){
  toggleAuthForms(mode === 'register');
  document.getElementById('authModal')?.classList.remove('hidden');
  // fókusz praktika
  setTimeout(()=> {
    const el = mode === 'register' ? document.getElementById('regName') : document.getElementById('loginEmail');
    el?.focus();
  }, 120);
}
function hideAuthModal(){ document.getElementById('authModal')?.classList.add('hidden'); }
function toggleAuthForms(showRegister=false){
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  if(showRegister){
    loginForm?.classList.add('hidden');
    registerForm?.classList.remove('hidden');
    document.getElementById('authTitle').innerText = 'Regisztráció';
  } else {
    loginForm?.classList.remove('hidden');
    registerForm?.classList.add('hidden');
    document.getElementById('authTitle').innerText = 'Bejelentkezés';
  }
}

/* register: létrehoz user, hash+salt tárolás */
async function handleRegister(e){
  // adatok
  const nameEl = document.getElementById('regName');
  const emailEl = document.getElementById('regEmail');
  const passEl = document.getElementById('regPassword');
  if(!nameEl || !emailEl || !passEl) return;
  const name = nameEl.value.trim();
  const email = emailEl.value.trim().toLowerCase();
  const pass = passEl.value;
  if(!name || !email || !pass || pass.length < 6) return alert('Adj meg érvényes adatokat (jelszó min. 6 karakter).');

  const users = JSON.parse(localStorage.getItem(USERS_KEY) || '[]');
  if(users.find(u=>u.email === email)) return alert('Ez az email már regisztrálva van.');

  const salt = genSalt();
  const hash = await hashPassword(pass, salt);

  users.push({name, email, hash, salt, created: Date.now()});
  localStorage.setItem(USERS_KEY, JSON.stringify(users));

  // automatikus bejelentkezés (session)
  localStorage.setItem(AUTH_KEY, JSON.stringify({name, email}));
  updateAuthUI();
  hideAuthModal();
  alert('Sikeres regisztráció. Beléptél.');
}

/* login: ellenőriz és bejelentkezik */
async function handleLogin(e){
  const emailEl = document.getElementById('loginEmail');
  const passEl = document.getElementById('loginPassword');
  if(!emailEl || !passEl) return;
  const email = emailEl.value.trim().toLowerCase();
  const pass = passEl.value;
  if(!email || !pass) return alert('Add meg az emailt és jelszót.');

  const users = JSON.parse(localStorage.getItem(USERS_KEY) || '[]');
  const user = users.find(u=>u.email === email);
  if(!user) return alert('Hibás email vagy jelszó.');

  const hash = await hashPassword(pass, user.salt);
  if(hash !== user.hash) return alert('Hibás email vagy jelszó.');

  localStorage.setItem(AUTH_KEY, JSON.stringify({name: user.name, email: user.email}));
  updateAuthUI();
  hideAuthModal();
  alert('Sikeres bejelentkezés.');
}

/* kijelentkezés */
function logout(){
  localStorage.removeItem(AUTH_KEY);
  updateAuthUI();
}

/* session lekérdezés */
function getCurrentUser(){
  return JSON.parse(localStorage.getItem(AUTH_KEY) || 'null');
}

/* UI frissítés: elrejti a bejelentkezés gombot, megmutatja a user menüt */
function updateAuthUI(){
  const user = getCurrentUser();
  const loginBtn = document.getElementById('loginBtn');
  const userMenu = document.getElementById('userMenu');
  const userName = document.getElementById('userName');
  if(user){
    loginBtn?.classList.add('hidden');
    if(userMenu){ userMenu.classList.remove('hidden'); if(userName) userName.innerText = user.name; }
  } else {
    loginBtn?.classList.remove('hidden');
    userMenu?.classList.add('hidden');
  }
}

/* Simple page protection: ha body[data-auth="true"] és nincs user, nyissa meg a modal-t */
function enforcePageProtection(){
  const body = document.body;
  if(!body) return;
  const requires = body.getAttribute('data-auth');
  if(requires === 'true' && !getCurrentUser()){
    showAuthModal('login');
    // rövid figyelmeztetés
    setTimeout(()=> alert('Ez az oldal csak bejelentkezett felhasználóknak érhető el. Jelentkezz be vagy regisztrálj.'), 120);
  }
}

/* kosár + vizuális visszajelzés */
let count = Number(localStorage.getItem('pr_cart_count') || 0);
function addToCart(){
  count++;
  localStorage.setItem('pr_cart_count', String(count));
  const el = document.getElementById("cartCount");
  if(el) el.innerText = count;
  flashAccent();
}
function flashAccent(){
  document.body.animate([{filter:'brightness(1)'},{filter:'brightness(1.06)'}],{duration:160,iterations:1});
}

// --- Comic viewer logic ---
const COMIC_IMAGES = [
  'PacificRimTalesFromTheDrift#1/RCO001_1463040706.jpg',
  'Pacific Rim tales from the Drift#1/RCO002_1463040706.jpg',
  'Pacific Rim tales from the Drift#1/RCO003_w_1463040706.jpg',
  'Pacific Rim tales from the Drift#1/RCO001_1463040706.jpg'
];

function ensureComicModal(){
  if(document.getElementById('comicModal')) return;
  // markup injected in HTML file for clarity; this is kept for safety
}

function openComicAt(index){
  const modal = document.getElementById('comicModal');
  const img = document.getElementById('comicImage');
  const indicator = document.getElementById('pageIndicator');
  if(!modal || !img || !indicator) return;
  index = Math.max(0, Math.min(COMIC_IMAGES.length - 1, index));
  img.src = COMIC_IMAGES[index];
  img.dataset.index = index;
  indicator.innerText = (index + 1) + ' / ' + COMIC_IMAGES.length;
  modal.classList.remove('hidden');
  // add backdrop element for blur effect
  if(!document.querySelector('.comic-modal-backdrop')){
    const d = document.createElement('div'); d.className = 'comic-modal-backdrop'; document.body.appendChild(d);
  }
  document.body.classList.add('comic-open');
}

function closeComic(){
  const modal = document.getElementById('comicModal');
  if(!modal) return;
  modal.classList.add('hidden');
  const d = document.querySelector('.comic-modal-backdrop'); if(d) d.remove();
  document.body.classList.remove('comic-open');
}

function showNext(){
  const img = document.getElementById('comicImage');
  if(!img) return;
  let idx = Number(img.dataset.index || 0);
  idx = Math.min(COMIC_IMAGES.length - 1, idx + 1);
  if(idx !== Number(img.dataset.index)) openComicAt(idx);
}
function showPrev(){
  const img = document.getElementById('comicImage');
  if(!img) return;
  let idx = Number(img.dataset.index || 0);
  idx = Math.max(0, idx - 1);
  if(idx !== Number(img.dataset.index)) openComicAt(idx);
}

// attach events to thumbs and controls
function initComicGallery(){
  const thumbs = document.querySelectorAll('.comic-thumb');
  thumbs.forEach(t=> t.addEventListener('click', (e)=>{
    const idx = Number(t.dataset.index || 0);
    openComicAt(idx);
  }));

  document.getElementById('comicClose')?.addEventListener('click', closeComic);
  document.getElementById('comicNext')?.addEventListener('click', showNext);
  document.getElementById('comicPrev')?.addEventListener('click', showPrev);

  // keyboard navigation
  document.addEventListener('keydown', (e)=>{
    const modal = document.getElementById('comicModal');
    if(!modal || modal.classList.contains('hidden')) return;
    if(e.key === 'ArrowRight') showNext();
    if(e.key === 'ArrowLeft') showPrev();
    if(e.key === 'Escape') closeComic();
  });
}

// call during initUI
const originalInitUI = initUI;
initUI = async function(){
  await originalInitUI();
  initComicGallery();
};

/* init */
document.addEventListener('DOMContentLoaded', ()=> {
  initUI().catch(err=> console.error('initUI error', err));
  // ha cartCount elem van, update
  const el = document.getElementById("cartCount");
  if(el) el.innerText = count;
});