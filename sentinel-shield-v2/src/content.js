// ==========================================
// SENTINEL SHIELD - Content Script
// Runs on every page at document_start
// ==========================================

(function () {
  'use strict';

  // ---- Scam detection patterns ----
  const CRYPTO_SCAM_PATTERNS = [
    /send\s+(0\.\d+|1|2|5|10)\s*(eth|btc|bnb|usdt|sol)/i,
    /double\s+your\s+(crypto|bitcoin|ethereum)/i,
    /elon\s+musk.*giveaway/i,
    /crypto\s+giveaway/i,
    /free\s+(bitcoin|ethereum|crypto)/i,
    /send.*receive.*back/i,
    /100%\s+profit/i,
    /guaranteed\s+return/i,
    /get\s+rich\s+quick/i,
    /bitcoin\s+investment/i,
    /crypto\s+mining\s+profit/i,
  ];

  const LOTTERY_PATTERNS = [
    /you\s+have\s+won/i,
    /congratulations.*winner/i,
    /claim\s+your\s+prize/i,
    /lottery\s+winner/i,
    /selected.*winner/i,
    /gift\s+card.*winner/i,
    /million\s+dollar.*winner/i,
  ];

  const SUPPORT_SCAM_PATTERNS = [
    /your\s+computer\s+has\s+been\s+(blocked|infected|hacked)/i,
    /call\s+microsoft\s+support/i,
    /call\s+apple\s+support/i,
    /windows\s+defender.*threat/i,
    /your\s+system\s+is\s+infected/i,
    /do\s+not\s+shut\s+down.*computer/i,
    /toll.?free.*1-8(00|44|55|66|77|88)/i,
  ];

  const GOV_IMPERSONATION_PATTERNS = [
    /irs.*refund/i,
    /social\s+security.*suspended/i,
    /fbi.*investigation/i,
    /arrest\s+warrant/i,
    /government\s+grant/i,
    /stimulus\s+check.*claim/i,
    /medicare.*benefit/i,
  ];

  const FAKE_CAPTCHA_PATTERNS = [
    /click\s+allow\s+to\s+prove/i,
    /press\s+allow\s+to\s+continue/i,
    /click\s+allow\s+to\s+access/i,
    /you\s+are\s+not\s+a\s+robot.*allow/i,
    /enable\s+notifications.*captcha/i,
  ];

  // ---- Analyze page text ----
  function analyzePageContent() {
    const text = document.body?.innerText || '';
    const html = document.documentElement?.innerHTML || '';
    const title = document.title || '';

    const scamTypes = [];
    let hasCryptoScam = false;
    let hasLotteryScam = false;
    let hasSupportScam = false;
    let hasGovImpersonation = false;
    let hasFakeCaptcha = false;
    let hasGiveaway = false;

    // Check patterns
    for (const p of CRYPTO_SCAM_PATTERNS) {
      if (p.test(text) || p.test(title)) { hasCryptoScam = true; break; }
    }
    for (const p of LOTTERY_PATTERNS) {
      if (p.test(text) || p.test(title)) { hasLotteryScam = true; break; }
    }
    for (const p of SUPPORT_SCAM_PATTERNS) {
      if (p.test(text) || p.test(title)) { hasSupportScam = true; break; }
    }
    for (const p of GOV_IMPERSONATION_PATTERNS) {
      if (p.test(text) || p.test(title)) { hasGovImpersonation = true; break; }
    }
    for (const p of FAKE_CAPTCHA_PATTERNS) {
      if (p.test(text) || p.test(html)) { hasFakeCaptcha = true; break; }
    }

    if (/giveaway/i.test(text) && /(free|win|claim)/i.test(text)) hasGiveaway = true;

    if (hasCryptoScam) scamTypes.push('Crypto Scam');
    if (hasLotteryScam) scamTypes.push('Lottery/Prize Scam');
    if (hasSupportScam) scamTypes.push('Tech Support Scam');
    if (hasGovImpersonation) scamTypes.push('Government Impersonation');
    if (hasFakeCaptcha) scamTypes.push('Fake CAPTCHA Malware');
    if (hasGiveaway) scamTypes.push('Fake Giveaway');

    // ---- Fake login page detection ----
    const forms = document.querySelectorAll('form');
    let hasFakeLogin = false;
    let hasHiddenForms = false;
    let hasCredentialHarvesting = false;

    forms.forEach(form => {
      const hasPassword = form.querySelector('input[type="password"]');
      const hasEmail = form.querySelector('input[type="email"], input[name*="user"], input[name*="email"]');
      const isHidden = getComputedStyle(form).display === 'none' || form.style.display === 'none';
      const action = form.action || '';
      const isSuspiciousAction = action && !action.startsWith(window.location.origin) && action !== '' && !action.startsWith('javascript:');

      if (isHidden && hasPassword) hasHiddenForms = true;
      if (hasPassword && isSuspiciousAction) {
        hasFakeLogin = true;
        hasCredentialHarvesting = true;
      }
      if (hasPassword && hasEmail && window.location.protocol !== 'https:') {
        hasFakeLogin = true;
      }
    });

    // ---- Clipboard hijacking ----
    let hasClipboardHijack = false;
    if (html.includes('clipboardData') || html.includes('ClipboardEvent') || html.includes('execCommand(\'copy\')')) {
      hasClipboardHijack = true;
    }

    // ---- Banking impersonation ----
    const bankNames = ['chase', 'wells fargo', 'bank of america', 'citibank', 'barclays', 'hsbc', 'paypal', 'zelle'];
    let hasBankImpersonation = false;
    const textLower = text.toLowerCase();
    for (const bank of bankNames) {
      if (textLower.includes(bank) && (hasFakeLogin || /verify|confirm|update|secure/i.test(text))) {
        hasBankImpersonation = true;
        scamTypes.push('Bank Impersonation');
        break;
      }
    }

    // ---- Tracker detection ----
    const trackers = detectTrackers();
    const privacyScore = Math.max(0, 100 - (trackers.total * 5));

    // ---- Fingerprinting detection ----
    const fpSignals = detectFingerprinting(html);

    chrome.runtime.sendMessage({
      type: 'CONTENT_ANALYSIS',
      payload: {
        scamTypes,
        hasCryptoScam,
        hasLotteryScam,
        hasSupportScam,
        hasGovImpersonation,
        hasFakeCaptcha,
        hasGiveaway,
        hasFakeLogin,
        hasHiddenForms,
        hasCredentialHarvesting,
        hasClipboardHijack,
        hasBankImpersonation,
        formCount: forms.length,
        trackers,
        privacyScore,
        fpSignals,
        pageTitle: title,
        metaDesc: document.querySelector('meta[name="description"]')?.content || '',
      }
    });

    chrome.runtime.sendMessage({
      type: 'PRIVACY_ANALYSIS',
      payload: {
        trackers,
        privacyScore,
        fpSignals,
        thirdPartyScripts: countThirdPartyScripts(),
      }
    });
  }

  function detectTrackers() {
    const TRACKER_LIST = {
      advertising: ['doubleclick.net', 'googlesyndication.com', 'adnxs.com', 'rubiconproject.com', 'pubmatic.com', 'openx.net', 'adsrvr.org', 'criteo.com', 'taboola.com', 'outbrain.com', 'moatads.com'],
      analytics: ['google-analytics.com', 'googletagmanager.com', 'hotjar.com', 'segment.com', 'mixpanel.com', 'amplitude.com', 'heap.io', 'fullstory.com', 'logrocket.com', 'clarity.ms'],
      social: ['facebook.net', 'connect.facebook', 'platform.twitter.com', 'linkedin.com/insight', 'snap.com/tr', 'pinterest.com/ct'],
      fingerprinting: ['fingerprintjs.com', 'fingerprint.com', 'threatmetrix.com'],
      other: ['quantserve.com', 'scorecardresearch.com', 'nielsen.com', 'comscore.com'],
    };

    const found = { advertising: [], analytics: [], social: [], fingerprinting: [], other: [], total: 0 };
    const scripts = document.querySelectorAll('script[src], img[src], link[href], iframe[src]');

    scripts.forEach(el => {
      const src = el.src || el.href || '';
      for (const [cat, domains] of Object.entries(TRACKER_LIST)) {
        for (const domain of domains) {
          if (src.includes(domain) && !found[cat].includes(domain)) {
            found[cat].push(domain);
            found.total++;
          }
        }
      }
    });

    return found;
  }

  function detectFingerprinting(html) {
    const signals = [];
    if (html.includes('canvas.toDataURL') || html.includes('getImageData')) signals.push('Canvas fingerprinting');
    if (html.includes('AudioContext') || html.includes('OscillatorNode')) signals.push('Audio fingerprinting');
    if (html.includes('RTCPeerConnection') || html.includes('webkitRTCPeerConnection')) signals.push('WebRTC IP leak');
    if (html.includes('getBattery') || html.includes('BatteryManager')) signals.push('Battery API tracking');
    if (html.includes('deviceMemory') || html.includes('hardwareConcurrency')) signals.push('Hardware fingerprinting');
    if (html.includes('fonts.check') || html.includes('FontFaceObserver')) signals.push('Font enumeration');
    if (html.includes('plugins.length') || html.includes('navigator.plugins')) signals.push('Plugin enumeration');
    return signals;
  }

  function countThirdPartyScripts() {
    const hostname = window.location.hostname;
    const scripts = document.querySelectorAll('script[src]');
    let third = 0;
    scripts.forEach(s => {
      try {
        if (new URL(s.src).hostname !== hostname) third++;
      } catch (e) {}
    });
    return third;
  }

  // ---- JS behavior analysis via injected script ----
  function injectAnalyzer() {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('src/injected.js');
    script.onload = () => script.remove();
    (document.head || document.documentElement).appendChild(script);
  }

  // ---- Listen for injected script results ----
  window.addEventListener('SENTINEL_JS_ANALYSIS', (e) => {
    chrome.runtime.sendMessage({
      type: 'JS_ANALYSIS',
      payload: e.detail
    });
  });

  // ---- Run analysis ----
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(analyzePageContent, 500);
      injectAnalyzer();
    });
  } else {
    setTimeout(analyzePageContent, 500);
    injectAnalyzer();
  }

  // ---- Password field protection ----
  document.addEventListener('focusin', (e) => {
    if (e.target.type === 'password') {
      const form = e.target.closest('form');
      const isHTTP = window.location.protocol !== 'https:';
      const isSuspicious = isHTTP || document.cookie.includes('suspicious');

      if (isHTTP) {
        showInPageWarning('⚠️ WARNING: You are entering a password on an HTTP page. Your credentials could be stolen!', 'danger');
      }
    }
  });

  function showInPageWarning(msg, level) {
    const existing = document.getElementById('sentinel-warning');
    if (existing) existing.remove();

    const div = document.createElement('div');
    div.id = 'sentinel-warning';
    div.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      z-index: 2147483647;
      background: ${level === 'danger' ? '#ff2244' : '#ff8800'};
      color: white;
      padding: 12px 18px;
      border-radius: 8px;
      font-family: system-ui, sans-serif;
      font-size: 13px;
      max-width: 350px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
      animation: sentinelSlide 0.3s ease;
      cursor: pointer;
    `;
    div.textContent = msg;
    div.onclick = () => div.remove();
    document.body?.appendChild(div);
    setTimeout(() => div?.remove(), 8000);
  }
})();
