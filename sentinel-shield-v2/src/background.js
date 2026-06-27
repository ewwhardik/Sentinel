// ==========================================
// SENTINEL SHIELD v2.0 - Background Service Worker
// Developed by Hardik — poop Organization India
// ==========================================

const TAB_DATA = new Map();
const ALERTS_STORE = new Map();

// ---- Suspicious patterns ----
const SUSPICIOUS_TLD = ['tk','ml','ga','cf','gq','xyz','top','click','download','stream','online','site','work','date','review','country','kim','cricket','science','party','gdn','buzz','vip','loan','win','bid','trade','racing','webcam','accountant','faith','men','ninja'];
const PHISHING_KEYWORDS = ['login','signin','account','verify','secure','update','confirm','banking','paypal','amazon','apple','microsoft','google','facebook','instagram','netflix','crypto','bitcoin','wallet','support','helpdesk','refund','prize','winner','lottery','giveaway','reward','free','claim','urgent','suspend','locked','alert','suspended','reactivate','unusual','activity'];
const BRAND_NAMES = ['paypal','amazon','apple','microsoft','google','facebook','instagram','netflix','chase','wellsfargo','bankofamerica','coinbase','binance','metamask','dropbox','twitter','linkedin','github','steam','ebay','alibaba'];
const KNOWN_SAFE_DOMAINS = ['google.com','youtube.com','microsoft.com','apple.com','amazon.com','facebook.com','twitter.com','x.com','github.com','stackoverflow.com','wikipedia.org','reddit.com','linkedin.com','netflix.com','paypal.com','bankofamerica.com','chase.com','wellsfargo.com','instagram.com','tiktok.com','cloudflare.com','mozilla.org','w3.org'];

// ---- Levenshtein distance ----
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[a.length][b.length];
}

function detectTyposquat(hostname) {
  const parts = hostname.split('.');
  const domain = parts.slice(-2, -1)[0] || '';
  for (const brand of BRAND_NAMES) {
    const dist = levenshtein(domain.toLowerCase(), brand);
    if (dist > 0 && dist <= 2 && domain.length >= 4) {
      return { detected: true, brand, distance: dist };
    }
  }
  return { detected: false };
}

function detectPunycode(hostname) {
  return hostname.includes('xn--') || /[^\x00-\x7F]/.test(hostname);
}

// ---- Advanced URL Analysis ----
function analyzeURL(url) {
  const issues = [];
  let score = 100;

  try {
    const u = new URL(url);
    const hostname = u.hostname;
    const tld = hostname.split('.').pop().toLowerCase();
    const path = u.pathname + u.search;
    const fullUrl = url.toLowerCase();

    // HTTPS check
    if (u.protocol !== 'https:') {
      issues.push({ type: 'danger', msg: 'No HTTPS — connection is not encrypted. Data can be intercepted.' });
      score -= 20;
    }

    // Suspicious TLD
    if (SUSPICIOUS_TLD.includes(tld)) {
      issues.push({ type: 'danger', msg: `Suspicious TLD: .${tld} — commonly used in free/throwaway domains` });
      score -= 25;
    }

    // Phishing keywords in URL
    const foundKeywords = PHISHING_KEYWORDS.filter(k => fullUrl.includes(k));
    if (foundKeywords.length >= 2) {
      issues.push({ type: 'danger', msg: `Phishing keywords in URL: ${foundKeywords.slice(0,3).join(', ')}` });
      score -= 30;
    } else if (foundKeywords.length === 1) {
      issues.push({ type: 'warning', msg: `Suspicious keyword in URL: ${foundKeywords[0]}` });
      score -= 10;
    }

    // Typosquatting
    const typo = detectTyposquat(hostname);
    if (typo.detected) {
      issues.push({ type: 'danger', msg: `Possible typosquatting of "${typo.brand}" (edit distance: ${typo.distance})` });
      score -= 40;
    }

    // Punycode / homograph
    if (detectPunycode(hostname)) {
      issues.push({ type: 'danger', msg: 'Punycode/homograph domain detected — may impersonate a trusted site' });
      score -= 35;
    }

    // Excessive subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > 3) {
      issues.push({ type: 'warning', msg: `Excessive subdomains (${subdomainCount}) — common in phishing URLs` });
      score -= 15;
    }

    // IP-based URL
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      issues.push({ type: 'danger', msg: 'IP address as domain — no identity verification possible' });
      score -= 30;
    }

    // Very long URL
    if (url.length > 200) {
      issues.push({ type: 'warning', msg: `Unusually long URL (${url.length} chars) — may obfuscate destination` });
      score -= 10;
    }

    // Brand in subdomain only
    for (const brand of BRAND_NAMES) {
      const parts2 = hostname.split('.');
      const mainDomain = parts2.slice(-2).join('.');
      if (!mainDomain.includes(brand)) {
        const sub = parts2.slice(0, -2).join('.');
        if (sub.includes(brand)) {
          issues.push({ type: 'danger', msg: `Brand "${brand}" in subdomain, not main domain — likely phishing` });
          score -= 40;
          break;
        }
      }
    }

    // Encoded characters
    if (path.includes('%') && (path.match(/%[0-9a-f]{2}/gi) || []).length > 5) {
      issues.push({ type: 'warning', msg: 'Heavily encoded URL path — may obfuscate content' });
      score -= 10;
    }

    // Data URI
    if (url.startsWith('data:')) {
      issues.push({ type: 'danger', msg: 'Data URI detected — can execute malicious content' });
      score -= 50;
    }

    // Redirect chains (double slashes or redirector pattern)
    if (/redirect|redir|url=http|goto=|return=|next=http/i.test(path)) {
      issues.push({ type: 'warning', msg: 'URL redirect parameter detected — may lead to a different destination' });
      score -= 10;
    }

    // @-symbol trick
    if (hostname.includes('@')) {
      issues.push({ type: 'danger', msg: 'URL contains @ symbol — real destination may be hidden after it' });
      score -= 40;
    }

    // Multiple dashes (common in fake domains)
    if ((hostname.match(/-/g) || []).length > 3) {
      issues.push({ type: 'warning', msg: `Domain contains many hyphens (${(hostname.match(/-/g)||[]).length}) — common phishing pattern` });
      score -= 10;
    }

    // Numbers in domain (imitation pattern)
    if (/\d{3,}/.test(hostname.split('.').slice(0,-1).join('.'))) {
      issues.push({ type: 'warning', msg: 'Domain contains number sequences — may imitate a legitimate site' });
      score -= 8;
    }

    if (issues.length === 0) {
      issues.push({ type: 'safe', msg: `Domain and URL structure appear clean` });
    }

  } catch (e) {
    issues.push({ type: 'danger', msg: 'Malformed URL — could not be parsed' });
    score -= 20;
  }

  return { score: Math.max(0, score), issues };
}

// ---- Trust level ----
function getTrustLevel(score) {
  if (score >= 80) return { level: 'SAFE', color: '#00f096', emoji: '🟢' };
  if (score >= 60) return { level: 'LOW RISK', color: '#ffcc00', emoji: '🟡' };
  if (score >= 35) return { level: 'SUSPICIOUS', color: '#ff8800', emoji: '🟠' };
  return { level: 'DANGEROUS', color: '#ff2244', emoji: '🔴' };
}

// ---- Badge update ----
function updateBadge(tabId, result) {
  const score = result.finalScore;
  let color = '#00ff88';
  let text = '✓';
  if (score < 35) { color = '#ff2244'; text = '!!'; }
  else if (score < 60) { color = '#ff8800'; text = '⚠'; }
  else if (score < 80) { color = '#ffcc00'; text = '~'; }
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// ---- Threat notification ----
function sendThreatNotification(result) {
  const trust = result.trustLevel;
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: `${trust.emoji} ${trust.level} — Sentinel Shield`,
    message: `${result.hostname}\nTrust Score: ${result.finalScore}/100\n${result.urlIssues[0]?.msg || 'Multiple threats detected'}`,
    priority: 2
  });
}

// ---- Main scan ----
async function scanTab(tabId, url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:') || url.startsWith('edge://') || url.startsWith('moz-extension://')) {
    return null;
  }

  const urlAnalysis = analyzeURL(url);
  let hostname = '';
  try { hostname = new URL(url).hostname; } catch (e) {}

  const isKnownSafe = KNOWN_SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));

  const result = {
    url,
    hostname,
    timestamp: Date.now(),
    urlScore: urlAnalysis.score,
    urlIssues: urlAnalysis.issues,
    isKnownSafe,
    isHTTPS: url.startsWith('https://'),
    contentData: null,
    jsData: null,
    privacyData: null,
    finalScore: 0,
    trustLevel: null,
  };

  let finalScore = isKnownSafe ? Math.max(urlAnalysis.score, 80) : urlAnalysis.score;
  result.finalScore = Math.max(0, Math.min(100, finalScore));
  result.trustLevel = getTrustLevel(result.finalScore);

  TAB_DATA.set(tabId, result);
  updateBadge(tabId, result);

  if (result.finalScore < 35 && !isKnownSafe) {
    sendThreatNotification(result);
  }

  return result;
}

// ---- Extension risk analysis ----
const HIGH_RISK_PERMS = ['<all_urls>','all_urls','tabs','cookies','webRequest','webRequestBlocking','clipboardRead','history','nativeMessaging','debugger','management','proxy','vpnProvider'];

function analyzeExtension(ext) {
  let riskScore = 0;
  const risks = [];
  const permissions = [...(ext.permissions||[]), ...(ext.hostPermissions||[])];

  for (const p of permissions) {
    if (HIGH_RISK_PERMS.includes(p)) { riskScore += 15; risks.push(`High-risk permission: ${p}`); }
  }
  if (!ext.homepageUrl) { riskScore += 10; risks.push('No developer homepage'); }
  if (ext.installType === 'development') { riskScore += 25; risks.push('Sideloaded (development) extension'); }
  if (!ext.enabled) { riskScore += 5; risks.push('Disabled but installed'); }
  if (permissions.length > 10) { riskScore += 10; risks.push(`Requests many permissions (${permissions.length})`); }

  const level = riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW';
  return {
    id: ext.id, name: ext.name, version: ext.version,
    enabled: ext.enabled, installType: ext.installType,
    homepageUrl: ext.homepageUrl, permissions,
    riskScore: Math.min(100, riskScore), riskLevel: level, risks,
  };
}

// ---- Cookie analysis ----
function analyzeCookies(cookies) {
  const result = { total: cookies.length, session: [], persistent: [], thirdParty: [], tracking: [], secure: [], insecure: [] };
  const TRACKING_DOMAINS = ['doubleclick','google-analytics','facebook','twitter','linkedin','hotjar','segment','mixpanel','amplitude','quantserve','scorecard','demdex','rubiconproject','pubmatic','openx','adsrvr','criteo','taboola','outbrain'];

  for (const cookie of cookies) {
    if (!cookie.expirationDate) result.session.push(cookie);
    else result.persistent.push(cookie);
    if (cookie.secure) result.secure.push(cookie);
    else result.insecure.push(cookie);
    const isTracking = TRACKING_DOMAINS.some(d => cookie.domain.includes(d)) ||
      /(_ga|_gid|_fbp|_pin_unauth|_uetsid|_uetvid|IDE|NID|HSID|SSID|APISID|SAPISID|fr|_scid)/.test(cookie.name);
    if (isTracking) result.tracking.push(cookie);
  }
  return result;
}

// ---- Event listeners ----
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    scanTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, tab => {
    if (tab?.url) scanTab(tabId, tab.url);
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (message.type === 'CONTENT_ANALYSIS') {
    if (tabId && TAB_DATA.has(tabId)) {
      const data = TAB_DATA.get(tabId);
      data.contentData = message.payload;
      let penalty = 0;
      const cd = message.payload;
      if (cd.hasFakeLogin) penalty += 25;
      if (cd.hasCryptoScam) penalty += 30;
      if (cd.hasHiddenForms) penalty += 20;
      if (cd.hasClipboardHijack) penalty += 35;
      if (cd.hasCredentialHarvesting) penalty += 30;
      if (cd.hasBankImpersonation) penalty += 25;
      if (cd.hasSupportScam) penalty += 20;
      if (cd.hasGovImpersonation) penalty += 25;
      if (cd.scamTypes?.length > 0) penalty += cd.scamTypes.length * 8;
      if (!data.isKnownSafe) {
        data.finalScore = Math.max(0, data.finalScore - penalty);
        data.trustLevel = getTrustLevel(data.finalScore);
      }
      updateBadge(tabId, data);
      TAB_DATA.set(tabId, data);
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === 'JS_ANALYSIS') {
    if (tabId && TAB_DATA.has(tabId)) {
      const data = TAB_DATA.get(tabId);
      data.jsData = message.payload;
      let penalty = 0;
      const jd = message.payload;
      if (jd.hasEval) penalty += 8;
      if (jd.hasCryptoMiner) penalty += 40;
      if (jd.hasKeylogger) penalty += 45;
      if (jd.hasObfuscation) penalty += 15;
      if (jd.hasSilentRedirect) penalty += 20;
      if (jd.hasCredentialStealing) penalty += 50;
      if (jd.hasDomManipulationAttack) penalty += 15;
      if (jd.hasWebAssemblyAbuse) penalty += 20;
      if (!data.isKnownSafe) {
        data.finalScore = Math.max(0, data.finalScore - penalty);
        data.trustLevel = getTrustLevel(data.finalScore);
      }
      updateBadge(tabId, data);
      TAB_DATA.set(tabId, data);
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === 'PRIVACY_ANALYSIS') {
    if (tabId && TAB_DATA.has(tabId)) {
      const data = TAB_DATA.get(tabId);
      data.privacyData = message.payload;
      TAB_DATA.set(tabId, data);
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === 'GET_TAB_DATA') {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const tab = tabs[0];
      if (tab?.id && TAB_DATA.has(tab.id)) {
        sendResponse({ data: TAB_DATA.get(tab.id) });
      } else if (tab?.url) {
        scanTab(tab.id, tab.url).then(result => {
          sendResponse({ data: result });
        });
      } else {
        sendResponse({ data: null });
      }
    });
    return true;
  }

  if (message.type === 'SCAN_NOW') {
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
      const tab = tabs[0];
      if (tab?.url) {
        TAB_DATA.delete(tab.id);
        const result = await scanTab(tab.id, tab.url);
        sendResponse({ data: result });
      } else {
        sendResponse({ data: null });
      }
    });
    return true;
  }

  if (message.type === 'GET_EXTENSIONS') {
    chrome.management.getAll(extensions => {
      const analyzed = extensions
        .filter(e => e.type === 'extension')
        .map(ext => analyzeExtension(ext));
      sendResponse({ data: analyzed });
    });
    return true;
  }

  if (message.type === 'GET_COOKIES') {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const tab = tabs[0];
      if (tab?.url) {
        chrome.cookies.getAll({ url: tab.url }, cookies => {
          sendResponse({ data: analyzeCookies(cookies) });
        });
      } else {
        sendResponse({ data: { total: 0, session: [], persistent: [], thirdParty: [], tracking: [], secure: [], insecure: [] } });
      }
    });
    return true;
  }
});
