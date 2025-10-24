# Jwt-token-refresh-and-expiry
A JWT (JSON Web Token) is used to securely transmit user data between a client and a server. It contains an expiry time (exp) that defines how long it remains valid. Once expired, the token cannot be used. To avoid forcing users to log in again, a refresh token is issued, which lasts longer and can be used to get a new access token.

<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>JWT Refresh Rotation Demo (Single HTML)</title>
<style>
  :root{font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial}
  body{margin:0;background:#0f172a;color:#e6eef8;display:flex;gap:1rem;min-height:100vh;padding:24px}
  .card{background:#0b1220;border-radius:12px;padding:16px;box-shadow:0 6px 18px rgba(2,6,23,.6);flex:1;min-width:320px}
  h1{margin:.25rem 0 1rem;font-size:1.2rem}
  label{display:block;margin-top:.5rem;font-size:.85rem;color:#9fb1d7}
  input, button, textarea, select{margin-top:.35rem;padding:.6rem;border-radius:8px;border:1px solid #1f2b46;background:#071229;color:#e6eef8;width:100%;box-sizing:border-box}
  button{cursor:pointer;border:none;padding:.6rem .8rem}
  .row{display:flex;gap:.6rem}
  .muted{color:#7f98bd;font-size:.85rem}
  pre{background:#071226;border-radius:8px;padding:8px;overflow:auto;height:140px}
  .small{font-size:.85rem}
  .log{background:#06121f;border-radius:8px;padding:12px;height:420px;overflow:auto;font-family:monospace;font-size:.85rem}
  .chips{display:flex;gap:.4rem;flex-wrap:wrap}
  .chip{background:#0b223a;padding:.25rem .5rem;border-radius:999px;font-size:.8rem;border:1px solid #12314a}
  .warn{color:#ffb4a2}
  footer{font-size:.8rem;color:#9fb1d7;margin-top:8px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
  @media(max-width:900px){body{flex-direction:column} .grid{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="card">
  <h1>JWT Refresh Rotation Demo — Single HTML</h1>
  <div class="muted">Simulated server + client in browser. Use the UI to register, login, call protected API, refresh tokens, and attempt token replay.</div>

  <hr style="opacity:.08;margin:12px 0">

  <div class="grid">
    <div>
      <label>Email<input id="email" value="alice@example.com"></label>
      <label>Password<input id="password" value="password123"></label>
      <div style="display:flex;gap:.5rem;margin-top:.6rem">
        <button id="btnRegister">Register</button>
        <button id="btnLogin">Login</button>
        <button id="btnLogout">Logout</button>
      </div>

      <label style="margin-top:12px">Actions</label>
      <div style="display:flex;gap:.5rem">
        <button id="btnProtected">Call Protected API</button>
        <button id="btnRefresh">Refresh Access Token</button>
        <button id="btnSimReplay">Simulate Replay (use old refresh)</button>
      </div>

      <label style="margin-top:12px">Client Storage (tokens stored here)</label>
      <div class="chips" id="clientTokens"></div>

      <label style="margin-top:12px">Server-side Store Snapshot</label>
      <pre id="serverStore"></pre>

      <footer>
        <div class="small">How to test replay:</div>
        <ol style="margin:.25rem 0 .5rem .9rem">
          <li>Login -> get refresh token (current).</li>
          <li>Click Refresh -> new refresh token replaces old (rotation).</li>
          <li>Click "Simulate Replay" to attempt using the old (now invalid) refresh token. Server will detect replay and revoke all user's sessions.</li>
        </ol>
        <div class="warn">Note: This is a simulation. In real systems the server persists refresh tokens and uses secure signing/secrets.</div>
      </footer>
    </div>

    <div>
      <label>Logs</label>
      <div class="log" id="log"></div>

      <label style="margin-top:12px">Latest Access Token (decoded)</label>
      <pre id="accessDecoded">{}</pre>

      <label style="margin-top:12px">Latest Refresh Token (raw)</label>
      <textarea id="rawRefresh" rows="3" readonly></textarea>
    </div>
  </div>
</div>

<script>
/*
  jwt-refresh-demo (single-file)
  - This simulates a server that issues access + refresh tokens.
  - Refresh tokens include a unique jti; server stores hashed token + jti.
  - On refresh: server verifies token, finds stored jti record, then ROTATES:
      delete old record -> create new refresh token (new jti) and save it.
  - If an already-used refresh token is presented (jti not found) it's treated as REPLAY:
      revoke all refresh tokens for that user.
  - All persistence is in-memory within this page (serverStore object).
*/

/* -------------------------
   Utility (demo-only "hash")
   -------------------------
   For simplicity and portability we use a tiny non-cryptographic "hash"
   (FNV-1a) to simulate storing a token hash. THIS IS NOT SECURE.
   In production, use bcrypt/argon2 and server-side secrets.
*/
function fnv1a(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
  }
  return (h >>> 0).toString(16);
}

function nowMs(){ return Date.now(); }
function secsFromNow(s){ return Math.floor((Date.now()/1000) + s); }

/* -------------------------
   "Server" state & functions
   ------------------------- */
const server = {
  users: [],             // { id, email, password }  (password plain here for demo)
  refreshTokens: [],     // { userId, jti, tokenHash, expiresAt }
  log(msg){ appendLog('[server] '+msg); updateServerView(); },
};

// tiny uid
function uid(prefix='u'){ return prefix + '-' + Math.random().toString(36).slice(2,10); }

/* Token generation (demo): tokens are simple base64 JSON + signature (using the demo hash) */
function makeToken(payload, secret='secret-demo', expiresSeconds=900){
  // payload object
  const header = { alg: 'HS256-demo', typ: 'JWT-demo' };
  const body = Object.assign({}, payload, { exp: secsFromNow(expiresSeconds) });
  const b64 = (obj)=> btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
  const sig = fnv1a(b64(header) + '.' + b64(body) + '.' + secret);
  return `${b64(header)}.${b64(body)}.${sig}`;
}

function decodeToken(token){
  try{
    const [h,b,s] = token.split('.');
    const parse = str => JSON.parse(decodeURIComponent(escape(atob(str))));
    return parse(b);
  }catch(e){
    return null;
  }
}

function verifyToken(token, secret='secret-demo'){
  const parts = token ? token.split('.') : [];
  if (parts.length !== 3) return false;
  const [h,b,s] = parts;
  const expected = fnv1a(h + '.' + b + '.' + secret);
  if (s !== expected) return false;
  const payload = decodeToken(token);
  if (!payload) return false;
  if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) return false;
  return payload;
}

/* Server API: register, login, refresh, logout, protected */
async function serverRegister(email,password){
  if (!email || !password) throw new Error('email+password required');
  if (server.users.find(u=>u.email===email)) throw new Error('user exists');
  const user = { id: uid('user'), email, password };
  server.users.push(user);
  server.log(`registered user ${email} (${user.id})`);
  return { id: user.id, email: user.email };
}

async function serverLogin(email,password){
  const user = server.users.find(u=>u.email===email);
  if (!user || user.password !== password) throw new Error('invalid credentials');
  // issue tokens
  const access = makeToken({ id: user.id, email: user.email }, 'access-secret', 15*60); // 15 min
  const jti = uid('jti');
  const refreshRaw = makeToken({ id: user.id, email: user.email, jti }, 'refresh-secret', 7*24*3600); // 7 days
  // store hash
  const tokenHash = fnv1a(refreshRaw);
  const payload = decodeToken(refreshRaw);
  server.refreshTokens.push({ userId: user.id, jti, tokenHash, expiresAt: (payload.exp*1000) });
  server.log(`login: issued access + refresh (jti=${jti}) to ${user.email}`);
  return { access, refresh: refreshRaw, jti };
}

/* Refresh: rotation + replay detection */
async function serverRefresh(presentedRefresh){
  // verify signature and expiry
  const payload = verifyToken(presentedRefresh, 'refresh-secret');
  if (!payload) throw new Error('invalid refresh token');

  const jti = payload.jti;
  // find stored record
  const stored = server.refreshTokens.find(r => r.jti === jti);

  if (!stored) {
    // replay or never-issued token: revoke all sessions for that user (if we can infer user)
    if (payload.id) {
      const uid = payload.id;
      server.refreshTokens = server.refreshTokens.filter(r => r.userId !== uid);
      server.log(`REPLAY DETECTED for user ${uid} — revoked all refresh tokens`);
    } else {
      server.log(`Invalid refresh token presented (unknown jti)`);
    }
    throw new Error('refresh token reuse detected — all sessions revoked');
  }

  // verify token hash matches stored hash (defense-in-depth)
  const presentedHash = fnv1a(presentedRefresh);
  if (presentedHash !== stored.tokenHash) {
    server.refreshTokens = server.refreshTokens.filter(r => r.userId !== stored.userId);
    server.log(`Hash mismatch for jti ${jti} — possible tampering. Revoked all for user ${stored.userId}`);
    throw new Error('refresh token invalid or replay detected — all sessions revoked');
  }

  // rotation: remove old token, issue a new refresh token (new jti)
  server.refreshTokens = server.refreshTokens.filter(r => r.jti !== jti);
  const user = server.users.find(u => u.id === stored.userId);
  if (!user) throw new Error('user not found');

  const newAccess = makeToken({ id: user.id, email: user.email }, 'access-secret', 15*60);
  const newJti = uid('jti');
  const newRefresh = makeToken({ id: user.id, email: user.email, jti: newJti }, 'refresh-secret', 7*24*3600);
  const newHash = fnv1a(newRefresh);
  const decoded = decodeToken(newRefresh);

  server.refreshTokens.push({ userId: user.id, jti: newJti, tokenHash: newHash, expiresAt: (decoded.exp*1000) });
  server.log(`Rotated refresh token: old jti ${jti} -> new jti ${newJti} for user ${user.email}`);
  return { access: newAccess, refresh: newRefresh };
}

async function serverLogout(presentedRefresh){
  try {
    const payload = verifyToken(presentedRefresh, 'refresh-secret');
    if (!payload) throw new Error('invalid');
    server.refreshTokens = server.refreshTokens.filter(r => r.jti !== payload.jti);
    server.log(`Logout: removed jti ${payload.jti}`);
  } catch(e){
    // idempotent
    server.log('Logout: token invalid or already removed');
  }
  return { ok: true };
}

async function serverProtected(accessToken){
  const payload = verifyToken(accessToken, 'access-secret');
  if (!payload) throw new Error('invalid or expired access token');
  return { message: 'Protected data', user: { id: payload.id, email: payload.email } };
}

/* -------------------------
   Client (browser) storage
   ------------------------- */
const client = {
  accessToken: null,
  refreshToken: null,
  // keep a copy of previously-used refresh tokens for replay testing
  previousRefreshTokens: [],
  setTokens({ access, refresh }){
    if (this.refreshToken) this.previousRefreshTokens.push(this.refreshToken);
    this.accessToken = access;
    this.refreshToken = refresh;
    uiUpdate();
  },
  clear(){
    this.accessToken = null;
    this.refreshToken = null;
    this.previousRefreshTokens = [];
    uiUpdate();
  }
};

/* -------------------------
   UI helpers
   ------------------------- */
const $ = id => document.getElementById(id);
function appendLog(txt){
  const el = $('log');
  el.innerText = `${new Date().toLocaleTimeString()} — ${txt}\n` + el.innerText;
}
function updateServerView(){
  const s = {
    users: server.users.map(u=>({id:u.id,email:u.email})),
    refreshTokens: server.refreshTokens.map(r=>({userId:r.userId,jti:r.jti,expiresAt:new Date(r.expiresAt).toLocaleString()}))
  };
  $('serverStore').innerText = JSON.stringify(s,null,2);
}
function uiUpdate(){
  // client tokens chips
  const chips = $('clientTokens');
  chips.innerHTML = '';
  const addChip = (label, text) => {
    const el = document.createElement('div');
    el.className = 'chip';
    el.title = text;
    el.innerText = label;
    chips.appendChild(el);
  };
  if (client.accessToken) addChip('access (present)', client.accessToken);
  if (client.refreshToken) addChip('refresh (present)', client.refreshToken);
  if (client.previousRefreshTokens.length) addChip('old refresh(s) stored', client.previousRefreshTokens.join('\n'));

  $('rawRefresh').value = client.refreshToken || '';
  $('accessDecoded').innerText = client.accessToken ? JSON.stringify(decodeToken(client.accessToken), null, 2) : '{}';
}

/* -------------------------
   Wire UI buttons
   ------------------------- */
$('btnRegister').addEventListener('click', async ()=>{
  try{
    const email = $('email').value.trim();
    const pwd = $('password').value;
    const res = await serverRegister(email,pwd);
    appendLog(`Client: registered ${res.email}`);
    updateServerView();
  }catch(e){ appendLog('Client error (register): '+e.message); }
});

$('btnLogin').addEventListener('click', async ()=>{
  try{
    const email = $('email').value.trim();
    const pwd = $('password').value;
    const res = await serverLogin(email,pwd);
    client.setTokens({ access: res.access, refresh: res.refresh });
    appendLog('Client: logged in — received tokens (refresh jti='+res.jti+')');
    updateServerView();
  }catch(e){ appendLog('Client error (login): '+e.message); }
});

$('btnProtected').addEventListener('click', async ()=>{
  try{
    const res = await serverProtected(client.accessToken);
    appendLog('Protected API success: ' + JSON.stringify(res));
  }catch(e){ appendLog('Protected API error: '+e.message); }
});

$('btnRefresh').addEventListener('click', async ()=>{
  try{
    const oldRefresh = client.refreshToken;
    const res = await serverRefresh(oldRefresh);
    client.setTokens({ access: res.access, refresh: res.refresh });
    appendLog('Client: refreshed tokens (rotation). Old refresh moved to previous list.');
    updateServerView();
  }catch(e){ appendLog('Client error (refresh): '+e.message); uiUpdate(); }
});

$('btnLogout').addEventListener('click', async ()=>{
  try{
    await serverLogout(client.refreshToken);
    client.clear();
    appendLog('Client: logged out (tokens removed client-side)');
    updateServerView();
  }catch(e){ appendLog('Logout error: '+e.message); }
});

/* Simulate replay: attempt to send a previously-used refresh token (one that was rotated away).
   This simulates an attacker using a stolen refresh after rotation. */
$('btnSimReplay').addEventListener('click', async ()=>{
  if (!client.previousRefreshTokens.length) {
    appendLog('No old refresh token stored to simulate replay. Do: login -> refresh -> then click this.');
    return;
  }
  const stolen = client.previousRefreshTokens[ client.previousRefreshTokens.length - 1 ];
  appendLog('Simulating replay: presenting previously-used refresh token to server...');
  try {
    const res = await serverRefresh(stolen);
    appendLog('Unexpected: server accepted old refresh (this should not happen).');
    client.setTokens({ access: res.access, refresh: res.refresh });
  } catch (e) {
    appendLog('Replay simulation result (server): ' + e.message);
    // in case of replay, client should be logged out and all sessions revoked
    client.clear();
    updateServerView();
  }
});

/* initialize UI */
appendLog('Demo ready. Register or use pre-filled credentials.');
updateServerView();
uiUpdate();

</script>
</body>
</html>
