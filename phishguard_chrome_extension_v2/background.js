// background.js (MV3 service worker)
importScripts('config.js');

/* =======================
   Core helpers / API
======================= */
const API = (p) => `${String(CONFIG.API_BASE).replace(/\/$/,'')}${p}`;

async function get(k){ const x = await chrome.storage.local.get([k]); return x[k]; }
async function set(obj){ await chrome.storage.local.set(obj); }

async function getTokens(){ return chrome.storage.local.get(['access','refresh']); }
async function saveTokens(access, refresh){
  const obj = {};
  if (typeof access === 'string') obj.access = access;
  if (typeof refresh === 'string') obj.refresh = refresh;
  if (Object.keys(obj).length) await chrome.storage.local.set(obj);
}
async function refreshAccessToken(){
  const { refresh } = await getTokens();
  if (!refresh) return null;
  try{
    const res = await fetch(API('/api/refresh'), { method:'POST', headers:{ Authorization:`Bearer ${refresh}` }});
    const j = await res.json().catch(()=>null);
    if (!res.ok || !j?.access_token) return null;
    await saveTokens(j.access_token, null);
    return j.access_token;
  }catch{ return null; }
}
async function fetchWithAuth(path, init = {}){
  const url = /^https?:\/\//i.test(path) ? path : API(path);
  const { access } = await getTokens();
  const headers = Object.assign({}, init.headers || {}, access ? { Authorization:`Bearer ${access}` } : {});
  let res = await fetch(url, { ...init, headers });
  if (res.status === 401 || res.status === 403){
    const newAccess = await refreshAccessToken();
    if (newAccess){
      const headers2 = Object.assign({}, init.headers || {}, { Authorization:`Bearer ${newAccess}` });
      res = await fetch(url, { ...init, headers: headers2 });
    }
  }
  return res;
}

function isHttpUrl(u){ return typeof u === 'string' && /^https?:\/\//i.test(u); }

// change this helper in background.js
async function recordReport(url, source, label = null, score = null){
  try{
    const payload = { url, source };
    if (label) payload.label = label;
    if (Number.isFinite(score)) payload.score = score;
    await fetchWithAuth('/api/report', {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify(payload)
    });
  }catch{/* ignore */}
}

/* =======================
   UI / badges / notify
======================= */
const SEVERITY = {
  OK:   { text: '',  color: [0,0,0,0] },
  WARN: { text: '!', color: [255,193,7,255] },
  BAD:  { text: 'PH', color: [220,53,69,255] },
};
function setBadge(tabId, sev, title) {
  const meta = SEVERITY[sev] || SEVERITY.OK;
  try { chrome.action.setBadgeText({ tabId, text: meta.text }); } catch {}
  try { chrome.action.setBadgeBackgroundColor({ tabId, color: meta.color }); } catch {}
  if (title) { try { chrome.action.setTitle({ tabId, title }); } catch {} }
}
function setBadgeCount(tabId, count, title){
  const txt = String(Math.max(1, Math.min(99, Number(count)||0)));
  try { chrome.action.setBadgeText({ tabId, text: txt }); } catch {}
  try { chrome.action.setBadgeBackgroundColor({ tabId, color: [220,53,69,255] }); } catch {}
  if (title) { try { chrome.action.setTitle({ tabId, title }); } catch {} }
}

const ICON_128 = chrome.runtime.getURL('icons/icon128.png');
async function notify(text){
  try{
    const id = `phishguard-${Date.now()}`;
    await chrome.notifications.create(id, {
      type: 'basic',
      iconUrl: ICON_128,
      title: 'PhishGuard',
      message: text,
      priority: 2,
      requireInteraction: false
    });
  }catch{
    try { chrome.action.setBadgeText({ text: '!' }); } catch {}
  }
}
async function notifyHighRiskSummary(tab, badCount, samples){
  const sampleHosts = [...new Set(samples.map(u => { try{ return new URL(u).hostname; }catch{ return u; } }))].slice(0,3);
  const host = (()=>{ try{ return new URL(tab.url).hostname; }catch{ return 'this site'; } })();
  const msg = `Found ${badCount} high-risk link${badCount>1?'s':''} on ${host}.\n`
            + (sampleHosts.length ? `Examples: ${sampleHosts.join(', ')}` : '');
  await notify(msg);
}

/* =======================
   State / threshold
======================= */
const STATE = {
  lastUrl: new Map(),
  lastLinksScan: new Map(),
  threshold: null,
  notified: new Map(),
};
const NOTIFY_TTL = 10*60*1000;
function shouldNotify(key){
  const now = Date.now();
  const last = STATE.notified.get(key) || 0;
  if (now - last < NOTIFY_TTL) return false;
  STATE.notified.set(key, now);
  return true;
}

async function getServerThreshold(){
  if (STATE.threshold !== null) return STATE.threshold;
  try {
    const r = await fetch(API('/api/health'));
    const j = await r.json().catch(()=>null);
    const t = Number(j?.threshold);
    STATE.threshold = Number.isFinite(t) ? t : 0.85;
  } catch { STATE.threshold = 0.85; }
  return STATE.threshold;
}

/* =======================
   Link collection
======================= */
const TRACKER_HINTS = /(googletagmanager|google-analytics|doubleclick|gstatic|hotjar|segment|newrelic|mixpanel|optimizely)/i;
const MAX_LINKS = 150;

function etldPlus1(host){
  const p = (host||'').split('.').filter(Boolean);
  return p.length <= 2 ? host : p.slice(-2).join('.');
}

async function collectPageLinks(tabId, externalOnly = true){
  let hrefs = [];
  try {
    const [inj] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const out = new Set();
        const ASSET_RE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|mjs|map|json|woff2?|ttf|eot|otf|mp[34]|webm|avi|mov|mkv|pdf|zip|rar|7z|gz|tar)(?:\?.*)?$/i;
        const isHttp = u => /^https?:\/\//i.test(u);
        const push = (u) => { try {
          if (!u) return;
          const abs = new URL(String(u), document.baseURI).href;
          if (!isHttp(abs)) return;
          const p = new URL(abs);
          if (ASSET_RE.test(p.pathname) || p.hash.startsWith('#')) return;
          out.add(abs);
        } catch{} };
        document.querySelectorAll('a[href]').forEach(a => push(a.getAttribute('href')));
        document.querySelectorAll('form[action]').forEach(f => push(f.getAttribute('action')));
        return Array.from(out).slice(0, 1000);
      }
    });
    hrefs = inj?.result || [];
  } catch {
    return [];
  }

  // filter tracking domains
  let list = hrefs.filter(u => { try { return !TRACKER_HINTS.test(new URL(u).hostname);} catch { return false; }});

  // external only?
  if (externalOnly){
    try {
      const tab = await chrome.tabs.get(tabId);
      const baseHost = etldPlus1(new URL(tab.url).hostname);
      list = list.filter(u => { try { return etldPlus1(new URL(u).hostname) !== baseHost; } catch { return false; }});
    } catch {}
  }

  const uniq = [...new Set(list)];
  return uniq.slice(0, MAX_LINKS);
}

/* =======================
   Labeling
======================= */
function labelFrom(score, thr){
  if (!Number.isFinite(score)) return {label:'error', sev:'WARN'};
  if (score >= Math.max(thr, 0.85)) return {label:'phish', sev:'BAD'};
  if (score >= Math.min(thr - 0.15, 0.60)) return {label:'suspicious', sev:'WARN'};
  return {label:'legit', sev:'OK'};
}

function allowlistOverride(url, cur){
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    if (u.protocol === 'https:' && !host.includes('xn--') && (host.endsWith('.gov') || host.endsWith('.edu'))){
      return {label:'legit', sev:'OK'};
    }
  } catch {}
  return cur;
}

/* =======================
   Badge check for active URL
======================= */
async function checkUrl(tabId, url){
  if (!isHttpUrl(url)) { setBadge(tabId, 'OK', 'Unsupported URL'); return; }
  const autoscan = (await get('autoscan')) ?? true;
  if (!autoscan) return;

  if (STATE.lastUrl.get(tabId) === url) return;
  STATE.lastUrl.set(tabId, url);

  const { access, refresh } = await getTokens();
  if (!access && !refresh){ setBadge(tabId, 'WARN', 'Not logged in'); return; }

  try{
    const res = await fetchWithAuth('/api/check', {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json().catch(()=>null);

    if (!res.ok || data?.error){
      setBadge(tabId, 'WARN', `Check failed: ${data?.error || res.status}`);
      return;
    }

    const thr = await getServerThreshold();
    const score = Number(data?.score ?? 0);
    const serverLabel = typeof data?.label === 'string' ? data.label.toLowerCase() : null;

    let meta = serverLabel
      ? ({ label: serverLabel, sev: (serverLabel==='phish' ? 'BAD' : (serverLabel==='suspicious' ? 'WARN' : 'OK')) })
      : labelFrom(score, thr);

    meta = allowlistOverride(url, meta);

    setBadge(tabId, meta.sev, `PhishGuard: ${meta.label} (${Number.isFinite(score)?score.toFixed(2):'–'})`);

    // NEW: record the page check so the dashboard has something to show
    await recordReport(url, 'badge', meta.label, score);

    if (meta.sev === 'BAD' && shouldNotify(`page:${url}`)){
      await notify(`PhishGuard: This page looks malicious (${Number.isFinite(score)?score.toFixed(2):'?'}).`);
    }
   
    const { recentChecks = [] } = await chrome.storage.local.get(['recentChecks']);
    const next = [{ ts: Date.now(), url, label: meta.label, score }, ...recentChecks].slice(0, 5);
    await chrome.storage.local.set({ recentChecks: next });

  }catch(e){
    setBadge(tabId, 'WARN', `Check error: ${String(e)}`);
  }
}

/* =======================
   Full page scan (links) + autoscan
======================= */
const LINK_AUTOSCAN_COOLDOWN_MS = 60_000;
const LINK_AUTOSCAN_DELAY_MS    = 1200;

async function scanPage(tabId){
  const { access, refresh } = await getTokens();
  if (!access && !refresh) return { ok:false, error:'Not logged in' };

  let links = [];
  try {
    const externalOnly = (await get('externalOnly')) ?? true;
    links = await collectPageLinks(tabId, externalOnly);
  } catch {}

  const thr = await getServerThreshold();

  const now = Date.now(), TTL = 60*60*1000;
  const { scoreCache = {} } = await chrome.storage.local.get(['scoreCache']);

  const results = [];
  const toCheck = [];
  for (const u of links){
    const c = scoreCache[u];
    if (c && (now - c.ts) < TTL){ results.push({ url:u, score:c.score, labelServer:c.label || null }); }
    else toCheck.push(u);
  }

  const CONC = 6;
  async function checkOne(u){
    try {
      const r = await fetchWithAuth('/api/check', {
        method:'POST',
        headers:{ 'Content-Type':'application/json' },
        body: JSON.stringify({ url: u })
      });
      const j = await r.json().catch(()=>null);
      const s = Number(j?.score ?? 0);
      const lab = typeof j?.label === 'string' ? j.label.toLowerCase() : null;
      results.push({ url:u, score:s, labelServer:lab });
      scoreCache[u] = { score:s, label:lab, ts: now };
    } catch {
      results.push({ url:u, score: NaN, labelServer:null, err: true });
    }
  }
  for (let i=0; i<toCheck.length; i+=CONC){
    await Promise.all(toCheck.slice(i,i+CONC).map(checkOne));
  }

  const entries = Object.entries(scoreCache).sort((a,b)=>b[1].ts-a[1].ts).slice(0,1500);
  await chrome.storage.local.set({ scoreCache: Object.fromEntries(entries) });

  const labeled = results.map(r => {
    const client = labelFrom(r.score, thr);
    let chosen = r.labelServer
      ? ({ label: r.labelServer, sev: (r.labelServer==='phish' ? 'BAD' : (r.labelServer==='suspicious' ? 'WARN' : 'OK')) })
      : client;
    chosen = allowlistOverride(r.url, chosen);
    return { ...r, labelClient: client.label, label: chosen.label, sev: chosen.sev };
  });

  labeled.sort((a,b)=> (b.score||0) - (a.score||0));
  const top = labeled.slice(0, 50);
  await set({ lastScan: top, lastScanMeta: { when: Date.now(), total: labeled.length, scanned: links.length } });

  const bad = labeled.filter(x=>x.sev==='BAD');

  // NEW: record a few interesting ones so the dashboard shows recent links
  const toReport = bad.slice(0, 5);                // prefer high-risk
  if (toReport.length === 0) toReport.push(...top.slice(0, 3)); // or a few top if nothing bad
  await Promise.allSettled(toReport.map(x => recordReport(x.url, 'autoscan', x.label, x.score)));

  return { ok:true, count: top.length, badCount: bad.length, warnCount: labeled.filter(x=>x.sev==='WARN').length, badSamples: bad.slice(0,3).map(x=>x.url) };
}

async function scheduleAutoScan(tab){
  if (!tab?.id || !isHttpUrl(tab.url)) return;
  const on = (await get('autoscanLinks')) ?? true;
  if (!on) return;

  const last = STATE.lastLinksScan.get(tab.id) || { url:'', ts:0 };
  const now = Date.now();
  if (last.url === tab.url && (now - last.ts) < LINK_AUTOSCAN_COOLDOWN_MS) return;

  setTimeout(async () => {
    try {
      const res = await scanPage(tab.id).catch(()=>null);
      STATE.lastLinksScan.set(tab.id, { url: tab.url, ts: Date.now() });

      if (res?.ok && res.badCount > 0){
        setBadgeCount(tab.id, res.badCount, `PhishGuard: ${res.badCount} high-risk link(s)`);
        if (shouldNotify(`links:${tab.url}`)){
          const t = await chrome.tabs.get(tab.id).catch(()=>null);
          if (t?.url === tab.url) await notifyHighRiskSummary(t, res.badCount, res.badSamples || []);
        }
      }
    } catch {}
  }, LINK_AUTOSCAN_DELAY_MS);
}

/* =======================
   Events
======================= */
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'complete' && tab && isHttpUrl(tab.url)){
    checkUrl(tabId, tab.url);
    scheduleAutoScan(tab);
  }
});
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(()=>null);
  if (tab && isHttpUrl(tab.url)){
    checkUrl(tabId, tab.url);
    scheduleAutoScan(tab);
  }
});
chrome.tabs.onRemoved?.addListener((tabId) => {
  STATE.lastUrl.delete(tabId);
  STATE.lastLinksScan.delete(tabId);
});

// Context menu: report page manually
chrome.runtime.onInstalled.addListener(async () => {
  try { await chrome.contextMenus.removeAll(); } catch {}
  chrome.contextMenus.create({ id:'phishguard-report', title:'PhishGuard: Report this page', contexts:['page'] });
});
chrome.contextMenus.onClicked?.addListener(async (info, tab) => {
  if (info.menuItemId !== 'phishguard-report' || !tab || !isHttpUrl(tab.url)) return;
  const { access, refresh } = await getTokens();
  if (!access && !refresh) return notify('Please log in from the popup first.');
  try{
    await recordReport(tab.url, 'context_menu');
    await notify('Reported ✓');
  }catch(e){ await notify(`Report error: ${String(e)}`); }
});

// Popup → background (manual scan)
chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  (async () => {
    if (msg?.type === 'scan'){
      const [tab] = await chrome.tabs.query({ active:true, currentWindow:true });
      if (!tab?.id || !isHttpUrl(tab.url)) return respond({ ok:false, error:'No HTTP tab' });
      const r = await scanPage(tab.id);
      respond(r);
    }
  })();
  return true;
});
