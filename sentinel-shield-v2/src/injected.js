// ==========================================
// SENTINEL SHIELD - Injected JS Analyzer
// Runs in page context to inspect scripts
// ==========================================

(function () {
  'use strict';

  const results = {
    hasEval: false,
    hasDocumentWrite: false,
    hasDynamicScriptLoad: false,
    hasObfuscation: false,
    hasCryptoMiner: false,
    hasWebAssemblyAbuse: false,
    hasBrowserFingerprinting: false,
    hasHiddenIframes: false,
    hasSilentRedirect: false,
    hasKeylogger: false,
    hasCredentialStealing: false,
    hasDomManipulationAttack: false,
    suspiciousEventListeners: [],
    scriptCount: 0,
    inlineScriptCount: 0,
    externalScriptCount: 0,
    obfuscationSigns: [],
    cryptoMinerSigns: [],
    details: [],
  };

  // ---- Collect all scripts ----
  const scripts = document.querySelectorAll('script');
  results.scriptCount = scripts.length;

  scripts.forEach((script) => {
    if (script.src) {
      results.externalScriptCount++;
    } else {
      results.inlineScriptCount++;
      const code = script.textContent || '';
      analyzeInlineScript(code);
    }
  });

  function analyzeInlineScript(code) {
    if (!code || code.length < 10) return;

    // eval() usage
    if (/\beval\s*\(/.test(code)) {
      results.hasEval = true;
      results.details.push('eval() detected — can execute dynamic/malicious code');
    }

    // document.write
    if (/document\s*\.\s*write\s*\(/.test(code)) {
      results.hasDocumentWrite = true;
      results.details.push('document.write() detected — can inject malicious content');
    }

    // Dynamic script loading
    if (/createElement\s*\(\s*['"]script['"]\s*\)/.test(code) || /new\s+Script\s*\(/.test(code)) {
      results.hasDynamicScriptLoad = true;
      results.details.push('Dynamic script loading detected');
    }

    // Obfuscation detection
    const obfuscationPatterns = [
      { pattern: /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/i, sign: 'Hex-encoded strings' },
      { pattern: /String\.fromCharCode\s*\([\d\s,]{20,}\)/i, sign: 'fromCharCode obfuscation' },
      { pattern: /atob\s*\(['"]/i, sign: 'Base64 decode (atob)' },
      { pattern: /\b_0x[a-f0-9]{4,}\b/i, sign: 'Obfuscator variable naming (_0x...)' },
      { pattern: /\bO0O0O\b|\bIlllII\b|\bl1l1l1\b/i, sign: 'Visual obfuscation characters' },
      { pattern: /\[\s*['"][a-z]+['"]\s*\]\s*\(/i, sign: 'Bracket notation method calls' },
      { pattern: /window\s*\[\s*['"][^'"]{1,10}['"]\s*\]\s*\(/i, sign: 'Dynamic window method access' },
    ];

    for (const { pattern, sign } of obfuscationPatterns) {
      if (pattern.test(code) && !results.obfuscationSigns.includes(sign)) {
        results.hasObfuscation = true;
        results.obfuscationSigns.push(sign);
      }
    }

    // Crypto miner detection
    const cryptoPatterns = [
      { pattern: /coinhive|cryptoloot|minero\.cc|jsecoin|coin-hive|coinlab/i, sign: 'Known miner domain' },
      { pattern: /\bwasm\b.*\b(miner|hash|worker)\b/i, sign: 'WASM miner pattern' },
      { pattern: /CryptoNight|stratum\+tcp|monero/i, sign: 'CryptoNight/Monero miner' },
      { pattern: /new\s+Worker.*blob/i, sign: 'Web Worker with blob (possible miner)' },
      { pattern: /SharedArrayBuffer.*postMessage/i, sign: 'SharedArrayBuffer miner pattern' },
    ];

    for (const { pattern, sign } of cryptoPatterns) {
      if (pattern.test(code) && !results.cryptoMinerSigns.includes(sign)) {
        results.hasCryptoMiner = true;
        results.cryptoMinerSigns.push(sign);
      }
    }

    // WebAssembly abuse
    if (/WebAssembly\s*\.\s*instantiate/.test(code) && (/eval|miner|hash|crypto/i.test(code))) {
      results.hasWebAssemblyAbuse = true;
      results.details.push('Suspicious WebAssembly usage detected');
    }

    // Keylogger detection
    const keyloggerPatterns = [
      /addEventListener\s*\(\s*['"]keydown['"]/i,
      /addEventListener\s*\(\s*['"]keyup['"]/i,
      /addEventListener\s*\(\s*['"]keypress['"]/i,
      /onkeydown\s*=/i,
    ];
    const hasKeyListener = keyloggerPatterns.some(p => p.test(code));
    if (hasKeyListener && (
      /XMLHttpRequest|fetch\s*\(/i.test(code) ||
      /localStorage|sessionStorage/i.test(code) ||
      /navigator\.sendBeacon/i.test(code)
    )) {
      results.hasKeylogger = true;
      results.details.push('Possible keylogger: key events + data exfiltration detected');
    }

    // Silent redirect
    const redirectPatterns = [
      /window\s*\.\s*location\s*=\s*['"]https?:\/\//i,
      /window\s*\.\s*location\s*\.\s*href\s*=/i,
      /window\s*\.\s*location\s*\.\s*replace\s*\(/i,
      /setTimeout\s*\(.*location/i,
    ];
    if (redirectPatterns.some(p => p.test(code))) {
      results.hasSilentRedirect = true;
      results.details.push('Silent/automatic redirect detected');
    }

    // Credential stealing
    const credPatterns = [
      { pattern: /password.*fetch|fetch.*password/i, sign: 'Credential fetch exfiltration' },
      { pattern: /\.value.*XMLHttpRequest|XMLHttpRequest.*\.value/i, sign: 'Form value exfiltration via XHR' },
      { pattern: /input\[type=.?password.?\].*send|send.*input\[type=.?password.?\]/i, sign: 'Password field send pattern' },
      { pattern: /\bgetElementsByName\s*\(\s*['"]password['"]\s*\)/i, sign: 'Password field targeting' },
      { pattern: /new Image.*src.*=(.*password|.*login|.*cred)/i, sign: 'Image beacon credential exfil' },
    ];
    for (const { pattern, sign } of credPatterns) {
      if (pattern.test(code)) {
        results.hasCredentialStealing = true;
        results.details.push(sign);
        break;
      }
    }

    // Clipboard hijack
    if (/addEventListener\s*\(\s*['"]copy['"]/.test(code) || /clipboardData\s*\.\s*setData/.test(code)) {
      results.details.push('Clipboard hijacking script detected');
    }

    // Hidden iframes
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(f => {
      const cs = window.getComputedStyle(f);
      const isHidden = f.style.display === 'none' || f.style.visibility === 'hidden'
        || f.style.opacity === '0' || (parseInt(f.style.width) === 0) || (parseInt(f.style.height) === 0)
        || cs.display === 'none';
      if (isHidden) {
        results.hasHiddenIframes = true;
        results.details.push(`Hidden iframe detected: ${f.src || 'no-src'}`);
      }
    });

    // Browser fingerprinting
    const fpPatterns = [
      /canvas.*toDataURL|toDataURL.*canvas/i,
      /AudioContext|webkitAudioContext/i,
      /navigator\.(plugins|languages|platform|userAgent|hardwareConcurrency|deviceMemory)/i,
      /screen\.(width|height|colorDepth|pixelDepth)/i,
    ];
    const fpCount = fpPatterns.filter(p => p.test(code)).length;
    if (fpCount >= 2) {
      results.hasBrowserFingerprinting = true;
      results.details.push(`Browser fingerprinting detected (${fpCount} signals)`);
    }
  }

  // ---- DOM Manipulation Attack ----
  const allLinks = document.querySelectorAll('a[href]');
  allLinks.forEach(link => {
    const href = link.href;
    if (href && href.startsWith('javascript:') && href.length > 30) {
      results.hasDomManipulationAttack = true;
      results.details.push('Suspicious javascript: URL in anchor tag');
    }
  });

  // ---- Send results to content script ----
  window.dispatchEvent(new CustomEvent('SENTINEL_JS_ANALYSIS', { detail: results }));
})();
