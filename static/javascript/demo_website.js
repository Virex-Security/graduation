// ==================== DEMO WEBSITE JS — ShopSecure ====================

const API = 'http://127.0.0.1:5000';
let gT = 0, gB = 0, gA = 0, gC = 0;

// ==================== STATS ====================

function upStats(blocked) {
  gT++;
  if (blocked) { gB++; gA++; } else gC++;
  document.getElementById('h-total').textContent   = gT;
  document.getElementById('h-blocked').textContent = gB;
  document.getElementById('h-attacks').textContent = gA;
  document.getElementById('h-clean').textContent   = gC;
}

// ==================== NAVIGATION ====================

function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  const tabs = document.querySelectorAll('.nav-tab');
  const map  = { home: 0, users: 1, orders: 2, attack: 3, logs: 4 };
  if (map[id] !== undefined) tabs[map[id]].classList.add('active');
  if (id === 'users')  searchUsers();
  if (id === 'orders') loadOrders();
  if (id === 'logs')   loadLogs();
}

// ==================== API HEALTH CHECK ====================

async function checkAPI() {
  try {
    const r = await fetch(`${API}/api/health`, { signal: AbortSignal.timeout(2000) });
    if (r.ok) {
      document.getElementById('api-dot').className  = 'api-dot';
      document.getElementById('api-txt').textContent = 'Virex Active';
      document.getElementById('api-txt').style.color = 'var(--green)';
    }
  } catch {
    document.getElementById('api-dot').className  = 'api-dot off';
    document.getElementById('api-txt').textContent = 'API Offline';
    document.getElementById('api-txt').style.color = 'var(--red)';
  }
}

checkAPI();
setInterval(checkAPI, 5000);

// ==================== LIVE FEED ====================

function addFeed(type, desc, cls) {
  const feed = document.getElementById('feed');
  const emp  = document.getElementById('feed-empty');
  if (emp) emp.remove();
  const d = document.createElement('div');
  d.className = 'feed-row';
  d.innerHTML = `<div class="fd ${cls}"></div>
    <div class="fb"><div class="ft">${type}</div><div class="fd2">${desc}</div></div>
    <div class="ftm">${new Date().toLocaleTimeString()}</div>`;
  feed.insertBefore(d, feed.firstChild);
  if (feed.children.length > 30) feed.removeChild(feed.lastChild);
}

// ==================== RESPONSE BOX ====================

function showRes(id, msg, cls) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `res ${cls}`;
  el.textContent = msg;
}

// ==================== LOGIN ====================

function sl(u, p) {
  document.getElementById('lu').value = u;
  document.getElementById('lp').value = p;
}

async function doLogin() {
  const u   = document.getElementById('lu').value;
  const p   = document.getElementById('lp').value;
  const btn = document.getElementById('btn-login');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>Sending...';
  try {
    const r = await fetch(`${API}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    });
    const d = await r.json();
    if      (r.status === 400) { showRes('r-login', `🚫 BLOCKED — ${d.error}`, 'bad');  addFeed('🚫 Attack Blocked',  `Login payload blocked: "${u.slice(0, 40)}"`, 'r'); upStats(true); }
    else if (r.status === 429) { showRes('r-login', `🔒 IP BLOCKED — ${d.error}`, 'bad'); addFeed('🔒 Brute Force Blocked', 'IP blocked after repeated failures', 'r'); upStats(true); }
    else if (r.status === 401) { showRes('r-login', '⚠️ Wrong credentials', 'warn'); addFeed('⚠️ Failed Login', `Invalid: "${u}"`, 'y'); upStats(false); }
    else                        { showRes('r-login', `✅ Welcome ${u}! Role: ${d.role || 'user'}`, 'ok'); addFeed('✅ Login Success', `Authenticated: "${u}"`, 'g'); upStats(false); }
  } catch (e) {
    showRes('r-login', '❌ API Offline — run simple_app.py', 'bad');
  }
  btn.disabled  = false;
  btn.textContent = 'Sign In';
}

async function bruteLoop() {
  const passwords = ['1234', 'pass', 'qwerty', 'letmein', 'monkey', 'abc123'];
  for (let i = 0; i < passwords.length; i++) {
    sl('admin', passwords[i]);
    await doLogin();
    await new Promise(r => setTimeout(r, 400));
  }
}

// ==================== USERS ====================

function setAndSearch(q) {
  document.getElementById('user-search').value = q;
  searchUsers();
}

async function searchUsers() {
  const q = document.getElementById('user-search').value;
  showRes('r-users', 'Sending...', 'idle');
  try {
    const r = await fetch(`${API}/api/users?search=${encodeURIComponent(q)}`);
    const d = await r.json();
    if (r.status === 400) {
      showRes('r-users', `🚫 BLOCKED — ${d.error}`, 'bad');
      addFeed('🚫 Attack Blocked', `User search blocked: "${q.slice(0, 50)}"`, 'r');
      upStats(true);
      document.getElementById('users-body').innerHTML =
        `<tr><td colspan="6" class="empty" style="color:var(--red)">🚫 Blocked by Virex</td></tr>`;
    } else {
      const rows = d.users.map(u => `<tr>
        <td style="color:var(--muted2)">#${u.id}</td>
        <td style="font-weight:600">${u.username}</td>
        <td style="color:var(--muted2)">${u.email}</td>
        <td><span class="badge r-${u.role}">${u.role}</span></td>
        <td style="color:var(--muted2)">${u.joined}</td>
        <td style="color:var(--accent)">${u.orders}</td>
      </tr>`).join('');
      document.getElementById('users-body').innerHTML =
        rows || `<tr><td colspan="6" class="empty">No users found</td></tr>`;
      showRes('r-users', `✅ ${d.total} user(s) returned`, 'ok');
      addFeed('✅ Users Fetched', `Search: "${q || 'all'}" — ${d.total} results`, 'g');
      upStats(false);
    }
  } catch {
    showRes('r-users', '❌ API Offline', 'bad');
  }
}

// ==================== ORDERS ====================

async function loadOrders() {
  try {
    const r  = await fetch(`${API}/api/orders`);
    const d  = await r.json();
    const sb = (s) => {
      const m = { delivered: 'bg', shipped: 'bb', pending: 'by', processing: 'bp' };
      return `<span class="badge ${m[s] || 'bb'}">${s}</span>`;
    };
    const rows = d.orders.map(o => `<tr>
      <td style="color:var(--muted2);font-family:monospace">#${o.id}</td>
      <td style="font-weight:600">${o.user}</td>
      <td>${o.product}</td>
      <td style="color:var(--green)">$${o.price}</td>
      <td>${sb(o.status)}</td>
      <td style="color:var(--muted2)">${o.date}</td>
    </tr>`).join('');
    document.getElementById('orders-body').innerHTML = rows;
  } catch {
    document.getElementById('orders-body').innerHTML =
      '<tr><td colspan="6" class="empty" style="color:var(--red)">API Offline</td></tr>';
  }
}

function setOrder(p) {
  document.getElementById('o-product').value = p;
}

async function placeOrder() {
  const user    = document.getElementById('o-user').value;
  const product = document.getElementById('o-product').value;
  const price   = document.getElementById('o-price').value;
  try {
    const r = await fetch(`${API}/api/orders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, product, price: parseFloat(price) })
    });
    const d = await r.json();
    if (r.status === 400) {
      showRes('r-order', `🚫 BLOCKED — ${d.error}`, 'bad');
      addFeed('🚫 Order Blocked', `Attack in product: "${product.slice(0, 40)}"`, 'r');
      upStats(true);
    } else {
      showRes('r-order', `✅ Order #${d.order.id} created`, 'ok');
      addFeed('✅ Order Placed', `"${product}" by ${user}`, 'g');
      upStats(false);
      loadOrders();
    }
  } catch {
    showRes('r-order', '❌ API Offline', 'bad');
  }
}

// ==================== PRODUCTS ====================

async function searchProducts() {
  const q   = document.getElementById('p-search').value;
  const cat = document.getElementById('p-cat').value;
  try {
    const r = await fetch(`${API}/api/products?search=${encodeURIComponent(q)}&category=${encodeURIComponent(cat)}`);
    const d = await r.json();
    if (r.status === 400) {
      showRes('r-products', `🚫 BLOCKED — ${d.error}`, 'bad');
      addFeed('🚫 Search Blocked', `"${q.slice(0, 50)}"`, 'r');
      upStats(true);
    } else {
      showRes('r-products', `✅ ${d.total} product(s): ${d.products.map(p => p.name).join(', ').slice(0, 80)}`, 'ok');
      addFeed('✅ Products Fetched', `${d.total} results for "${q || 'all'}"`, 'g');
      upStats(false);
    }
  } catch {
    showRes('r-products', '❌ API Offline', 'bad');
  }
}

// ==================== ATTACK LAB ====================

async function fireAttack(type, payId, resId) {
  const payload = document.getElementById(payId).value;
  showRes(resId, 'Firing attack...', 'idle');
  try {
    const r = await fetch(`${API}/api/data`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: payload, notes: 'attack test' })
    });
    const d = await r.json();
    if (r.status === 400 || r.status === 429) {
      showRes(resId, `🚫 BLOCKED by Virex — ${d.error}`, 'bad');
      addFeed(`🚫 ${type.toUpperCase()} Blocked`, `"${payload.slice(0, 50)}"`, 'r');
      upStats(true);
    } else {
      showRes(resId, '⚠️ Passed — check Virex dashboard', 'warn');
      addFeed(`⚠️ ${type.toUpperCase()} Passed`, `"${payload.slice(0, 50)}"`, 'y');
      upStats(false);
    }
  } catch {
    showRes(resId, '❌ API Offline', 'bad');
  }
}

async function fireBrute() {
  const user  = document.getElementById('bf-user').value;
  const count = parseInt(document.getElementById('bf-count').value);
  const btn   = document.getElementById('btn-bf');
  btn.disabled = true;
  const passwords = ['123456', 'password', 'admin', 'qwerty', 'letmein', 'abc123', 'monkey', '111111', '1234', 'pass'];
  let blocked = false;

  for (let i = 0; i < count; i++) {
    document.getElementById('bf-prog').textContent =
      `Attempt ${i + 1}/${count} — trying: "${passwords[i % passwords.length]}"`;
    try {
      const r = await fetch(`${API}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: passwords[i % passwords.length] })
      });
      const d = await r.json();
      upStats(false);
      if (r.status === 429) {
        showRes('r-bf', `🔒 IP BLOCKED after ${i + 1} attempts — ${d.error}`, 'bad');
        addFeed('🔒 IP Blocked', `Brute force blocked after ${i + 1} attempts`, 'r');
        upStats(true);
        blocked = true;
        break;
      }
      addFeed('🔑 Failed Login', `Attempt ${i + 1}: "${passwords[i % passwords.length]}"`, 'y');
    } catch {
      showRes('r-bf', '❌ API Offline', 'bad');
      break;
    }
    await new Promise(r => setTimeout(r, 300));
  }

  if (!blocked) showRes('r-bf', `⚠️ ${count} attempts sent — check dashboard`, 'warn');
  document.getElementById('bf-prog').textContent = '';
  btn.disabled    = false;
  btn.textContent = '🚀 Start Brute Force';
}

async function fireRateLimit() {
  const count = parseInt(document.getElementById('rl-count').value);
  document.getElementById('btn-rl').disabled = true;
  let hits = 0;

  for (let i = 0; i < count; i++) {
    document.getElementById('rl-prog').textContent = `Request ${i + 1}/${count}`;
    try {
      const r = await fetch(`${API}/api/products?search=test${i}`);
      if (r.status === 429) {
        hits++;
        addFeed('⚡ Rate Limited', `Request ${i + 1} rate limited`, 'r');
        upStats(true);
      } else {
        upStats(false);
      }
    } catch {}
    await new Promise(r => setTimeout(r, 50));
  }

  showRes('r-rl', hits > 0 ? `⚡ ${hits}/${count} requests rate-limited` : `✅ All ${count} passed`, 'warn');
  document.getElementById('rl-prog').textContent = '';
  document.getElementById('btn-rl').disabled    = false;
  document.getElementById('btn-rl').textContent = '🚀 Flood API';
}

// ==================== LOGS ====================

async function loadLogs() {
  try {
    const r = await fetch(`${API}/api/logs`);
    const d = await r.json();
    if (!d.logs || d.logs.length === 0) {
      document.getElementById('logs-body').innerHTML =
        '<tr><td colspan="6" class="empty">No logs yet — make some requests first</td></tr>';
      return;
    }
    const rows = d.logs.map(l => `<tr>
      <td style="font-family:monospace;color:var(--muted2)">${l.time}</td>
      <td><span class="badge ${l.method === 'GET' ? 'bb' : 'bp'}">${l.method}</span></td>
      <td style="font-family:monospace;font-size:11px">${l.endpoint}</td>
      <td style="color:var(--muted2);font-size:11px">${l.ip}</td>
      <td><span class="badge ${l.status < 400 ? 'bg' : 'br'}">${l.status}</span></td>
      <td style="font-size:11px;color:var(--muted2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.payload || '—'}</td>
    </tr>`).join('');
    document.getElementById('logs-body').innerHTML = rows;
  } catch {
    document.getElementById('logs-body').innerHTML =
      '<tr><td colspan="6" class="empty" style="color:var(--red)">API Offline</td></tr>';
  }
}

// ==================== AUTO REFRESH & EVENT LISTENERS ====================

setInterval(() => {
  if (document.getElementById('page-logs').classList.contains('active')) loadLogs();
}, 3000);

document.getElementById('lu').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
document.getElementById('lp').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
