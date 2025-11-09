(async function () {
  // Elements
  const emailEl    = document.getElementById('email');
  const passwordEl = document.getElementById('password');
  const loginBtn   = document.getElementById('loginBtn');
  const meBtn      = document.getElementById('meBtn');
  const refreshBtn = document.getElementById('refreshBtn');
  const scanBtn    = document.getElementById('scanBtn');
  const autoscanEl = document.getElementById('autoscan');
  const externalEl = document.getElementById('externalOnly');

  const output    = document.getElementById('output');
  const accessOut = document.getElementById('accessOut');
  const status    = document.getElementById('status');
  const reportList= document.getElementById('reportList');
  const checkList = document.getElementById('checkList');
  const scanTable = document.querySelector('#scanTable tbody');
  const autoscanLinksEl = document.getElementById('autoscanLinks');

  // ---------- API helpers ----------
  const BASE = String(CONFIG.API_BASE || "").replace(/\/+$/,''); // no trailing slash
  const API  = `${BASE}/api`;                                   // always /api

  function show(msg, ok=false){
    output.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);
    status.textContent = ok ? 'OK' : '';
    status.className   = ok ? 'small ok' : 'small err';
  }
  const truncate = tok => tok ? tok.slice(0,25) + '...' : '';

  async function saveTokens(access, refresh){
    await chrome.storage.local.set({ access, refresh });
    accessOut.textContent = truncate(access);
  }
  async function getTokens(){
    const {access,refresh} = await chrome.storage.local.get(['access','refresh']);
    accessOut.textContent = truncate(access);
    return {access,refresh};
  }
  async function getSetting(key, def){ const v=await chrome.storage.local.get([key]); return v[key]===undefined? def : v[key]; }
  async function setSetting(key, val){ await chrome.storage.local.set({[key]:val}); }

  async function expectJSON(res, url){
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (!ct.includes('application/json')) {
      const text = await res.text();
      throw new Error(`Expected JSON from ${url} (status ${res.status}). First bytes: ${text.slice(0,120)}`);
    }
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || res.statusText || `HTTP ${res.status}`);
    return json;
  }

  async function postJSON(path, data, token){
    const url = `${API}${path}`;
    const headers = {'Content-Type':'application/json'};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(url, { method:'POST', headers, body: JSON.stringify(data || {}) });
    return expectJSON(res, url);
  }

  async function getJSON(path, token){
    const url = `${API}${path}`;
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(url, { headers });
    return expectJSON(res, url);
  }

  // ---------- Auth ----------
  async function login(){
    const email = emailEl.value.trim().toLowerCase();
    const password = passwordEl.value;
    if(!email || !password){ show('Please enter email and password'); return; }
    try{
      const auth = await postJSON('/login', { email, password });
      await saveTokens(auth.access_token, auth.refresh_token);
      show('Logged in', true);
      await loadRecentReports();
    }catch(e){ show(String(e)); }
  }

  async function me(){
    const {access} = await getTokens();
    if(!access){ show('No access token. Log in first.'); return; }
    try{
      const info = await getJSON('/me', access);
      show(info, true);
    }catch(e){ show(String(e)); }
  }

  async function refresh(){
    const {refresh} = await getTokens();
    if(!refresh){ show('No refresh token. Log in first.'); return; }
    try{
      const data = await postJSON('/refresh', {}, refresh);
      // keep the same refresh, just swap access
      const old = await getTokens();
      await saveTokens(data.access_token, old.refresh);
      show('Access token refreshed', true);
    }catch(e){ show(String(e)); }
  }

  // ---------- Lists ----------
  async function loadRecentReports(){
    reportList.innerHTML = '';
    try{
      const {access}=await getTokens(); if(!access) return;
      const items = await getJSON('/reports?limit=5', access);
      if(!Array.isArray(items)) return;
      for(const i of items){
        const li=document.createElement('li');
        const when = i.created_at ? new Date(i.created_at).toLocaleString() : '';
        li.textContent = `${when} — ${i.url}`;
        reportList.appendChild(li);
      }
    }catch(_){}
  }

  async function loadLastChecks(){
    checkList.innerHTML='';
    const items=(await chrome.storage.local.get(['recentChecks'])).recentChecks || [];
    for(const i of items){
      const li=document.createElement('li');
      const when=new Date(i.ts).toLocaleString();
      const score=Number(i.score??0).toFixed(2);
      li.textContent=`${when} — ${i.label} (${score}) — ${i.url}`;
      checkList.appendChild(li);
    }
  }

  // ---------- Scan rendering ----------
  function labelClass(label, score){
    if (score >= 0.85 || /phish|malicious/i.test(label)) return 'label-bad';
    if (score >= 0.60 || /suspicious/i.test(label)) return 'label-warn';
    return 'label-ok';
  }

  async function renderScan(){
    scanTable.innerHTML = '';
    const { lastScan = [] } = await chrome.storage.local.get(['lastScan']);
    for (const r of lastScan) {
      const tr=document.createElement('tr');
      const tdL=document.createElement('td');
      const tdU=document.createElement('td');
      const tdS=document.createElement('td');
      const label = r.labelClient || r.labelServer || 'unknown';
      tdL.textContent = label;
      tdL.className = labelClass(label, Number(r.score||0));
      tdU.textContent = r.url;
      tdS.textContent = isFinite(r.score) ? Number(r.score).toFixed(2) : '—';
      tdS.className = 'score';
      tr.append(tdL, tdU, tdS);
      scanTable.appendChild(tr);
    }
  }

  async function runScan(){
    scanBtn.disabled=true; scanBtn.textContent='Scanning...';
    const res = await chrome.runtime.sendMessage({ type:'scan' });
    if (!res?.ok && res?.error) output.textContent = res.error;
    await renderScan();
    scanBtn.disabled=false; scanBtn.textContent='Scan this page';
  }

  // ---------- Events ----------
  loginBtn.addEventListener('click', login);
  meBtn.addEventListener('click', me);
  refreshBtn.addEventListener('click', refresh);
  scanBtn.addEventListener('click', runScan);

  autoscanEl.addEventListener('change', async () => {
    await setSetting('autoscan', autoscanEl.checked);
  });
  autoscanLinksEl.addEventListener('change', async () => {
    await setSetting('autoscanLinks', autoscanLinksEl.checked);
  });
  externalEl.addEventListener('change', async () => {
    await setSetting('externalOnly', externalEl.checked);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.recentChecks) loadLastChecks();
  });

  // ---------- Init ----------
  await getTokens();
  await (async ()=>{
    try {
      // quick ping so users get a nice error if server is down
      await getJSON('/health'); // no auth required
    } catch (e) {
      show(`API not reachable at ${API}: ${e.message}`);
    }
  })();

  await loadSettings();
  await loadRecentReports();
  await loadLastChecks();
  await renderScan();
})();
