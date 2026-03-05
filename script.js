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
  'PacificRimTalesFromTheDrift1/RCO001_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO002_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO003_w_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO004_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO005_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO006_w_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO007_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO008_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO009_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO010_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO011_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO012_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO013_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO014_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO015_w_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO016_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO017_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO018_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO019_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO020_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO021_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO022_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO023_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO024_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO025_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO026_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO027_w_1463040706.jpg',
  'PacificRimTalesFromTheDrift1/RCO028_1463040706.jpg'
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
  resetZoom();
}

function closeComic(){
  const modal = document.getElementById('comicModal');
  if(!modal) return;
  modal.classList.add('hidden');
  const d = document.querySelector('.comic-modal-backdrop'); if(d) d.remove();
  document.body.classList.remove('comic-open');
  resetZoom();
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

// Zoom state
let comicZoom = { level: 100, offsetX: 0, offsetY: 0 };

function updateZoomDisplay(){
  const zoomLevel = document.getElementById('zoomLevel');
  if(zoomLevel) zoomLevel.innerText = comicZoom.level + '%';
}

function applyZoom(){
  const img = document.getElementById('comicImage');
  const frame = document.getElementById('comicFrame');
  if(!img || !frame) return;
  
  img.style.zoom = comicZoom.level / 100;
  
  if(comicZoom.level > 100){
    frame.classList.add('zoomed');
    img.classList.remove('fit-height');
  } else {
    frame.classList.remove('zoomed');
    img.classList.add('fit-height');
  }
  
  updateZoomDisplay();
}

function zoomInComic(){
  comicZoom.level = Math.min(200, comicZoom.level + 25);
  applyZoom();
}

function zoomOutComic(){
  comicZoom.level = Math.max(100, comicZoom.level - 25);
  applyZoom();
}

function resetZoom(){
  comicZoom = { level: 100, offsetX: 0, offsetY: 0 };
  applyZoom();
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

  // Zoom controls
  document.getElementById('zoomIn')?.addEventListener('click', zoomInComic);
  document.getElementById('zoomOut')?.addEventListener('click', zoomOutComic);
  document.getElementById('zoomReset')?.addEventListener('click', resetZoom);

  // keyboard navigation
  document.addEventListener('keydown', (e)=>{
    const modal = document.getElementById('comicModal');
    if(!modal || modal.classList.contains('hidden')) return;
    if(e.key === 'ArrowRight') showNext();
    if(e.key === 'ArrowLeft') showPrev();
    if(e.key === 'Escape') closeComic();
    if(e.key === '+' || e.key === '=') zoomInComic();
    if(e.key === '-') zoomOutComic();
    if(e.key === '0') resetZoom();
  });
}

// --- Comic Selection (Reading List) ---
const COMICS_LIST = [
  { id: 'drift1', name: 'Tales From The Drift - 1. rész', series: 'Tales From The Drift', year: 2015, status: 'popular', url: 'tales_from_the_drift.html', cover: 'PacificRimTalesFromTheDrift1/RCO001_1463040706.jpg' },
  { id: 'drift2', name: 'Tales From The Drift - 2. rész', series: 'Tales From The Drift', year: 2015, status: 'popular', url: 'tales_from_the_drift.html', cover: 'PacificRimTalesFromTheDrift2/RCO001_1463040781.jpg' },
  { id: 'drift3', name: 'Tales From The Drift - 3. rész', series: 'Tales From The Drift', year: 2015, status: 'new', url: 'tales_from_the_drift.html', cover: 'PacificRimTalesFromTheDrift3/RCO001_1463040848.jpg' },
  { id: 'drift4', name: 'Tales From The Drift - 4. rész', series: 'Tales From The Drift', year: 2015, status: 'new', url: 'tales_from_the_drift.html', cover: 'PacificRimTalesFromTheDrift4/RCO001_1463040923.jpg' },
  { id: 'final1', name: 'Final Breach - 1. rész', series: 'Final Breach', year: 2026, status: 'available', url: 'final_breach.html', cover: 'PacificRimFinalBreach/FBCover.png' }
];

const READING_LIST_KEY = 'pr_reading_list';

function initComicSelector(){
  if(document.body.dataset.page !== 'kepregeny') return;
  
  renderComicCatalog();
  setupComicSelectionEvents();
  loadReadingList();
}

function renderComicCatalog(){
  const catalog = document.getElementById('comicCatalog');
  if(!catalog) return;
  
  catalog.innerHTML = COMICS_LIST.map(comic => `
    <a href="${comic.url}" class="comic-card-link">
      <div class="comic-card" data-comic-id="${comic.id}">
        <div class="comic-cover-container">
          ${comic.cover ? `<img src="${comic.cover}" alt="${comic.name}" class="comic-cover">` : `<div class="comic-cover-placeholder">📖</div>`}
          <span class="comic-status-badge ${comic.status}">${comic.status === 'new' ? '🆕 Új' : comic.status === 'available' ? '📦 Előrendelhető' : '⭐ Népszerű'}</span>
        </div>
        <div class="comic-header">
          <h3>${comic.name}</h3>
          <span class="comic-year">${comic.year}</span>
        </div>
        <div class="comic-meta">
          <span class="comic-series">${comic.series}</span>
        </div>
        <div class="comic-actions">
          <button class="btn-select-comic" data-comic-id="${comic.id}" onclick="event.stopPropagation(); event.preventDefault();">
            <span class="btn-text">Hozzáadás elolvasotthoz</span>
          </button>
        </div>
      </div>
    </a>
  `).join('');
}

function setupComicSelectionEvents(){
  // Kiválasztás
  document.querySelectorAll('.btn-select-comic').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      const comicId = e.target.closest('button').dataset.comicId;
      toggleComicSelection(comicId);
    });
  });

  // Szűrés és rendezés
  document.getElementById('filterSort')?.addEventListener('change', (e) => {
    sortComicCatalog(e.target.value);
  });

  // Nézet gombok
  document.getElementById('viewGridBtn')?.addEventListener('click', () => switchView('grid'));
  document.getElementById('viewListBtn')?.addEventListener('click', () => switchView('list'));

  // Törlés gombak
  document.getElementById('clearAllBtn')?.addEventListener('click', clearAllSelections);
  document.getElementById('viewSelectedBtn')?.addEventListener('click', showSelectedPanel);
  document.getElementById('closePanel')?.addEventListener('click', hideSelectedPanel);
  document.getElementById('clearList')?.addEventListener('click', clearReadingList);
  document.getElementById('downloadList')?.addEventListener('click', exportReadingList);
}

function toggleComicSelection(comicId){
  const list = getReadingList();
  const idx = list.indexOf(comicId);
  
  if(idx === -1){
    list.push(comicId);
  } else {
    list.splice(idx, 1);
  }
  
  saveReadingList(list);
  updateSelectionUI();
}

function getReadingList(){
  const stored = localStorage.getItem(READING_LIST_KEY);
  return stored ? JSON.parse(stored) : [];
}

function saveReadingList(list){
  localStorage.setItem(READING_LIST_KEY, JSON.stringify(list));
}

function updateSelectionUI(){
  const list = getReadingList();
  
  // Szám frissítése
  document.getElementById('selectedCount').innerText = list.length;
  
  // Gombok frissítése
  document.querySelectorAll('.btn-select-comic').forEach(btn => {
    const comicId = btn.dataset.comicId;
    const isSelected = list.includes(comicId);
    btn.classList.toggle('selected', isSelected);
    btn.querySelector('.btn-text').innerText = isSelected ? '✓ Elolvasandóban' : 'Hozzáadás elolvasotthoz';
  });
  
  // Panel frissítése
  renderSelectedList();
}

function renderSelectedList(){
  const list = getReadingList();
  const selectedList = document.getElementById('selectedList');
  if(!selectedList) return;
  
  if(list.length === 0){
    selectedList.innerHTML = '<p class="empty-message">Még nincs képregény az elolvasandók között.</p>';
    return;
  }
  
  selectedList.innerHTML = list.map(comicId => {
    const comic = COMICS_LIST.find(c => c.id === comicId);
    if(!comic) return '';
    return `
      <div class="selected-item">
        <div class="item-info">
          <h4>${comic.name}</h4>
          <p>${comic.series} (${comic.year})</p>
        </div>
        <button class="btn-remove-from-list" data-comic-id="${comicId}" aria-label="Eltávolítás">✕</button>
      </div>
    `;
  }).join('');
  
  // Eltávolítási gombok
  document.querySelectorAll('.btn-remove-from-list').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const comicId = e.target.dataset.comicId;
      toggleComicSelection(comicId);
    });
  });
}

function clearAllSelections(){
  if(confirm('Biztosan törlöd az összes választást?')){
    saveReadingList([]);
    updateSelectionUI();
  }
}

function clearReadingList(){
  clearAllSelections();
  hideSelectedPanel();
}

function showSelectedPanel(){
  const panel = document.getElementById('selectedPanel');
  if(panel) panel.classList.remove('hidden');
}

function hideSelectedPanel(){
  const panel = document.getElementById('selectedPanel');
  if(panel) panel.classList.add('hidden');
}

function loadReadingList(){
  updateSelectionUI();
}

function switchView(view){
  const catalog = document.getElementById('comicCatalog');
  if(!catalog) return;
  
  catalog.classList.remove('grid-view', 'list-view');
  catalog.classList.add(view === 'grid' ? 'grid-view' : 'list-view');
  
  document.getElementById('viewGridBtn')?.setAttribute('aria-pressed', view === 'grid');
  document.getElementById('viewListBtn')?.setAttribute('aria-pressed', view === 'list');
  
  document.getElementById('viewGridBtn')?.classList.toggle('active', view === 'grid');
  document.getElementById('viewListBtn')?.classList.toggle('active', view === 'list');
}

function sortComicCatalog(sortBy){
  if(sortBy === 'name'){
    COMICS_LIST.sort((a, b) => a.name.localeCompare(b.name, 'hu'));
  } else if(sortBy === 'recent'){
    COMICS_LIST.sort((a, b) => b.year - a.year);
  }
  renderComicCatalog();
  updateSelectionUI();
}

function exportReadingList(){
  const list = getReadingList();
  const comics = list.map(id => COMICS_LIST.find(c => c.id === id)).filter(Boolean);
  
  const text = 'Elolvasandó képregények - Pacific Rim\n' +
    '=====================================\n\n' +
    comics.map((c, i) => `${i+1}. ${c.name} (${c.year})`).join('\n') +
    '\n\nExportálva: ' + new Date().toLocaleString('hu-HU');
  
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'elolvasandok.txt';
  a.click();
  URL.revokeObjectURL(url);
}

const originalInitUI = initUI;
initUI = async function(){
  await originalInitUI();
  initComicGallery();
  initComicSelector();
};

/* init */
document.addEventListener('DOMContentLoaded', ()=> {
  initUI().catch(err=> console.error('initUI error', err));
  // ha cartCount elem van, update
  const el = document.getElementById("cartCount");
  if(el) el.innerText = count;
});