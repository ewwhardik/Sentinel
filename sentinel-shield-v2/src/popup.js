// ==========================================
// SENTINEL SHIELD v2.0 - Popup UI
// Developed by Hardik — poop Organization India
// ==========================================

let currentData = null;
const alertsLog = [];

// ---- Tab switching (FIXED) ----
function switchTab(name) {
  // Update tab styles
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === name);
  });
  // Update panels
  document.querySelectorAll('.panel').forEach(p => {
    p.classList.toggle('active', p.id === `panel-${name}`);
  });

  // Load tab-specific data
  if (name === 'extensions') loadExtensions();
  if (name === 'cookies') loadCookies();
  if (name === 'alerts') renderAlerts();
  if (name === 'privacy' && currentData) renderPrivacy(currentData);
  if (name === 'js' && currentData) renderJS(currentData);
  if (name === 'threats' && currentData) renderThreats(currentData);
}

// ---- Open external link in new tab ----
function openLink(url) {
  chrome.tabs.create({ url: url, active: true });
  return false;
}

// ---- Load data from background ----
function loadData() {
  chrome.runtime.sendMessage({ type: 'GET_TAB_DATA' }, (resp) => {
    if (chrome.runtime.lastError) {
      console.warn('Sentinel: background error', chrome.runtime.lastError);
      setTimeout(loadData, 1500);
      return;
    }
    if (resp?.data) {
      currentData = resp.data;
      renderAll(resp.data);
    } else {
      showScanningState();
      setTimeout(loadData, 1200);
    }
  });
}

function showScanningState() {
  document.getElementById('scoreNum').textContent = '--';
  document.getElementById('trustBadge').textContent = 'SCANNING…';
  document.getElementById('trustBadge').style.cssText = 'color:var(--text-muted);border-color:var(--text-muted)44';
  document.getElementById('scoreDomain').textContent = 'Please wait...';
  document.getElementById('headerUrl').textContent = 'Scanning...';
}

// ---- Main render ----
function renderAll(data) {
  if (!data) return;

  // Header URL
  try {
    document.getElementById('headerUrl').textContent = new URL(data.url).hostname;
  } catch(e) {
    document.getElementById('headerUrl').textContent = data.hostname || '—';
  }

  // Score
  const score = data.finalScore ?? 0;
  const trust = data.trustLevel || getTrustLevel(score);

  updateScoreCircle(score, trust);
  updateMeter(score);

  const badge = document.getElementById('trustBadge');
  badge.textContent = trust.emoji + ' ' + trust.level;
  badge.style.cssText = `color:${trust.color};border-color:${trust.color}44;background:${trust.color}0d;`;

  document.getElementById('scoreDomain').textContent = data.hostname || '—';
  document.getElementById('scoreMeta').textContent = data.isKnownSafe
    ? '✓ Recognized trusted domain'
    : 'Score based on URL, content & behavior analysis';

  // Score card glow
  document.getElementById('scoreCard').style.setProperty('--score-glow', trust.color + '0f');

  // Stats
  const httpsStat = document.getElementById('stat-https');
  httpsStat.textContent = data.isHTTPS ? 'HTTPS' : 'HTTP ⚠';
  httpsStat.style.color = data.isHTTPS ? 'var(--accent-green)' : 'var(--accent-red)';

  const certStat = document.getElementById('stat-cert');
  certStat.textContent = data.isHTTPS ? 'Valid' : 'None';
  certStat.style.color = data.isHTTPS ? 'var(--accent-green)' : 'var(--accent-red)';

  const trackers = data.privacyData?.trackers || data.contentData?.trackers;
  const trackerCount = trackers?.total ?? 0;
  const trackerStat = document.getElementById('stat-trackers');
  trackerStat.textContent = trackerCount;
  trackerStat.style.color = trackerCount > 5 ? 'var(--accent-orange)' : trackerCount > 0 ? 'var(--accent-yellow)' : 'var(--accent-green)';

  const threatCount = (data.urlIssues?.filter(i => i.type === 'danger')?.length || 0)
    + (data.contentData?.scamTypes?.length || 0);
  const threatStat = document.getElementById('stat-threats');
  threatStat.textContent = threatCount;
  threatStat.style.color = threatCount > 0 ? 'var(--accent-red)' : 'var(--accent-green)';

  const scriptStat = document.getElementById('stat-scripts');
  scriptStat.textContent = data.jsData?.scriptCount ?? '—';

  // Cookie count
  loadCookieCount(data);

  // URL Issues
  const urlEl = document.getElementById('urlIssuesList');
  urlEl.innerHTML = '';
  if (data.urlIssues?.length > 0) {
    data.urlIssues.forEach(issue => urlEl.appendChild(createIssueItem(issue)));
  } else {
    urlEl.innerHTML = makeIssueHTML('safe', '✅', 'URL Analysis Clean', 'No suspicious patterns detected in the URL structure');
  }

  // Render other tabs if they're active
  const activePanel = document.querySelector('.panel.active');
  if (activePanel) {
    const tabName = activePanel.id.replace('panel-', '');
    if (tabName === 'threats') renderThreats(data);
    if (tabName === 'js') renderJS(data);
    if (tabName === 'privacy') renderPrivacy(data);
  } else {
    // Always pre-render threats and JS in background
    renderThreats(data);
    renderJS(data);
    renderPrivacy(data);
  }

  // Status bar
  document.getElementById('connectionStatus').textContent = data.isHTTPS ? '🔒 Encrypted' : '⚠️ Not Encrypted';
  document.getElementById('lastScanTime').textContent = 'Scanned: ' + new Date(data.timestamp || Date.now()).toLocaleTimeString();

  // Auto alert
  if (score < 35) addAlert('danger', '🔴 Dangerous Website Detected', `${data.hostname} has a trust score of only ${score}/100`, data.urlIssues?.[0]?.msg);
  else if (score < 60) addAlert('warn', '🟠 Suspicious Website', `${data.hostname} shows suspicious patterns`, 'Review the Threats tab for details');
  else addAlert('safe', '🟢 Website Appears Safe', `${data.hostname} passed security checks`, `Trust Score: ${score}/100`);
}

// ---- Render: Threats ----
function renderThreats(data) {
  const el = document.getElementById('threatsList');
  const checkEl = document.getElementById('contentIssuesList');
  const advEl = document.getElementById('advancedChecksList');

  if (!el) return;

  const cd = data?.contentData;
  if (!cd) {
    el.innerHTML = '<div class="empty"><div class="icon">⏳</div>Content analysis pending...<div class="sub">Results arrive shortly after page loads</div></div>';
    if (checkEl) checkEl.innerHTML = '';
    if (advEl) advEl.innerHTML = '';
    return;
  }

  const threats = [];
  if (cd.hasCryptoScam) threats.push({ icon: '💰', title: 'Crypto Scam Detected', desc: 'Page contains cryptocurrency scam patterns — fake giveaways or investment fraud', level: 'danger' });
  if (cd.hasLotteryScam) threats.push({ icon: '🎰', title: 'Lottery / Prize Scam', desc: 'Page uses lottery winner or prize claim language to deceive users', level: 'danger' });
  if (cd.hasSupportScam) threats.push({ icon: '📞', title: 'Tech Support Scam', desc: 'Fake tech support warnings detected — do NOT call any phone numbers shown', level: 'danger' });
  if (cd.hasGovImpersonation) threats.push({ icon: '🏛️', title: 'Government Impersonation', desc: 'Page may impersonate a government agency (IRS, FBI, Social Security)', level: 'danger' });
  if (cd.hasFakeCaptcha) threats.push({ icon: '🤖', title: 'Fake CAPTCHA Push Malware', desc: 'Fake "verify you are human" designed to grant notification permissions', level: 'danger' });
  if (cd.hasFakeLogin) threats.push({ icon: '🔑', title: 'Suspicious Login Form', desc: 'Login form with suspicious behavior or HTTP connection detected', level: 'danger' });
  if (cd.hasHiddenForms) threats.push({ icon: '👻', title: 'Hidden Forms Detected', desc: 'Invisible forms may capture input without your knowledge', level: 'danger' });
  if (cd.hasCredentialHarvesting) threats.push({ icon: '🕷️', title: 'Credential Harvesting', desc: 'Form appears to submit credentials to an external or suspicious endpoint', level: 'danger' });
  if (cd.hasBankImpersonation) threats.push({ icon: '🏦', title: 'Financial Impersonation', desc: 'Page appears to impersonate a bank or financial institution', level: 'danger' });
  if (cd.hasClipboardHijack) threats.push({ icon: '📋', title: 'Clipboard Hijacking', desc: 'Scripts may replace clipboard content (e.g. swap crypto wallet addresses)', level: 'danger' });
  if (cd.hasGiveaway) threats.push({ icon: '🎁', title: 'Suspicious Giveaway', desc: 'Page promotes a giveaway that exhibits fraudulent patterns', level: 'warning' });

  if (threats.length === 0) {
    el.innerHTML = makeIssueHTML('safe', '✅', 'No Scam Patterns Detected', 'Content analysis found no known scam or phishing patterns');
  } else {
    el.innerHTML = threats.map(t =>
      makeIssueHTML(t.level, t.icon, t.title, t.desc)
    ).join('');
  }

  // Content checks
  if (checkEl) {
    const checks = [
      { label: 'Form Count', icon: '📝', value: cd.formCount ?? 0, ok: (cd.formCount ?? 0) < 6, warn: (cd.formCount ?? 0) >= 6 },
      { label: 'Login Form', icon: '🔐', value: cd.hasFakeLogin ? '⚠ Suspicious' : '✓ Clean', ok: !cd.hasFakeLogin },
      { label: 'Hidden Forms', icon: '👻', value: cd.hasHiddenForms ? '⚠ Found' : '✓ None', ok: !cd.hasHiddenForms },
      { label: 'Clipboard', icon: '📋', value: cd.hasClipboardHijack ? '⚠ Risk' : '✓ Clean', ok: !cd.hasClipboardHijack },
      { label: 'Bank Reference', icon: '🏦', value: cd.hasBankImpersonation ? '⚠ Detected' : '✓ None', ok: !cd.hasBankImpersonation },
      { label: 'Cred Harvest', icon: '🕷️', value: cd.hasCredentialHarvesting ? '⚠ Risk' : '✓ Safe', ok: !cd.hasCredentialHarvesting },
    ];
    checkEl.innerHTML = checks.map(c => `
      <div class="js-item">
        <div class="label"><span>${c.icon}</span>${esc(c.label)}</div>
        <span class="badge ${c.ok ? 'ok' : 'bad'}">${esc(String(c.value))}</span>
      </div>
    `).join('');
  }

  // Advanced checks
  if (advEl) {
    const jd = data.jsData;
    if (!jd) {
      advEl.innerHTML = '<div class="empty" style="padding:10px 0"><div class="icon">⏳</div>Script analysis pending...</div>';
    } else {
      const adv = [
        { label: 'Keylogger Pattern', icon: '⌨️', ok: !jd.hasKeylogger, val: jd.hasKeylogger ? '🔴 DETECTED' : '✓ Clean' },
        { label: 'Credential Stealing', icon: '🔑', ok: !jd.hasCredentialStealing, val: jd.hasCredentialStealing ? '🔴 DETECTED' : '✓ Clean' },
        { label: 'Crypto Miner', icon: '⛏️', ok: !jd.hasCryptoMiner, val: jd.hasCryptoMiner ? '🔴 MINING' : '✓ Clean' },
        { label: 'Code Obfuscation', icon: '🌀', ok: !jd.hasObfuscation, val: jd.hasObfuscation ? '⚠ Obfuscated' : '✓ Clean' },
        { label: 'Silent Redirect', icon: '↪️', ok: !jd.hasSilentRedirect, val: jd.hasSilentRedirect ? '⚠ Found' : '✓ Clean' },
        { label: 'DOM Attack', icon: '💉', ok: !jd.hasDomManipulationAttack, val: jd.hasDomManipulationAttack ? '⚠ Found' : '✓ Clean' },
      ];
      advEl.innerHTML = adv.map(a => `
        <div class="js-item">
          <div class="label"><span>${a.icon}</span>${esc(a.label)}</div>
          <span class="badge ${a.ok ? 'ok' : 'bad'}">${esc(a.val)}</span>
        </div>
      `).join('');
    }
  }
}

// ---- Render: JS Scripts ----
function renderJS(data) {
  const el = document.getElementById('jsList');
  const statsEl = document.getElementById('jsStats');
  const detailEl = document.getElementById('jsDetails');

  if (!el) return;

  const jd = data?.jsData;
  if (!jd) {
    el.innerHTML = '<div class="empty"><div class="icon">⏳</div>Script analysis pending...<div class="sub">Analysis completes after page fully loads</div></div>';
    if (statsEl) statsEl.innerHTML = '';
    if (detailEl) detailEl.innerHTML = '';
    return;
  }

  const checks = [
    { label: 'eval() Usage', icon: '⚡', key: 'hasEval', danger: true, desc: 'Can execute dynamic/untrusted code' },
    { label: 'document.write()', icon: '✍️', key: 'hasDocumentWrite', danger: true, desc: 'Can inject malicious HTML' },
    { label: 'Dynamic Script Load', icon: '📦', key: 'hasDynamicScriptLoad', danger: false, desc: 'Loads scripts at runtime' },
    { label: 'Code Obfuscation', icon: '🌀', key: 'hasObfuscation', danger: true, desc: 'Code intentionally hidden' },
    { label: 'Crypto Miner', icon: '⛏️', key: 'hasCryptoMiner', danger: true, desc: 'Mining cryptocurrency via your CPU' },
    { label: 'WebAssembly Abuse', icon: '🧱', key: 'hasWebAssemblyAbuse', danger: true, desc: 'WASM used suspiciously' },
    { label: 'Browser Fingerprint', icon: '🖐️', key: 'hasBrowserFingerprinting', danger: false, desc: 'Identifying your device' },
    { label: 'Hidden Iframes', icon: '🖼️', key: 'hasHiddenIframes', danger: true, desc: 'Invisible embedded frames' },
    { label: 'Silent Redirect', icon: '↪️', key: 'hasSilentRedirect', danger: true, desc: 'Automatic redirection detected' },
    { label: 'Keylogger Pattern', icon: '⌨️', key: 'hasKeylogger', danger: true, desc: 'Key events + data exfiltration' },
    { label: 'Credential Stealing', icon: '🔑', key: 'hasCredentialStealing', danger: true, desc: 'Password exfiltration pattern' },
    { label: 'DOM Attack', icon: '💉', key: 'hasDomManipulationAttack', danger: true, desc: 'Malicious DOM manipulation' },
  ];

  el.innerHTML = checks.map(c => {
    const val = jd[c.key];
    const badgeClass = val ? (c.danger ? 'bad' : 'warn') : 'ok';
    const badgeText = val ? (c.danger ? 'DETECTED' : 'PRESENT') : 'CLEAN';
    return `
      <div class="js-item">
        <div class="label"><span>${c.icon}</span>${esc(c.label)}</div>
        <span class="badge ${badgeClass}">${badgeText}</span>
      </div>
    `;
  }).join('');

  // Stats
  if (statsEl) {
    statsEl.innerHTML = `
      <div class="js-item"><div class="label"><span>📊</span>Total Scripts</div><span class="badge info">${jd.scriptCount ?? 0}</span></div>
      <div class="js-item"><div class="label"><span>📝</span>Inline Scripts</div><span class="badge info">${jd.inlineScriptCount ?? 0}</span></div>
      <div class="js-item"><div class="label"><span>🌐</span>External Scripts</div><span class="badge info">${jd.externalScriptCount ?? 0}</span></div>
    `;
  }

  // Details
  if (detailEl) {
    let html = '';
    if (jd.details?.length > 0) {
      html += jd.details.map(d =>
        makeIssueHTML('warning', '⚠️', 'Suspicious Pattern', d)
      ).join('');
    }
    if (jd.obfuscationSigns?.length > 0) {
      html += jd.obfuscationSigns.map(s =>
        makeIssueHTML('warning', '🌀', 'Obfuscation', s)
      ).join('');
    }
    if (jd.cryptoMinerSigns?.length > 0) {
      html += jd.cryptoMinerSigns.map(s =>
        makeIssueHTML('danger', '⛏️', 'Mining Activity', s)
      ).join('');
    }
    if (!html) {
      html = makeIssueHTML('safe', '✅', 'No Malicious Patterns', 'Script analysis found no suspicious inline behavior');
    }
    detailEl.innerHTML = html;
  }
}

// ---- Render: Privacy ----
function renderPrivacy(data) {
  const priv = data?.privacyData || data?.contentData;
  const numEl = document.getElementById('privacyScoreNum');
  const fillEl = document.getElementById('privacyScoreFill');
  const fpEl = document.getElementById('fpList');
  const trackerEl = document.getElementById('trackerList');
  const thirdEl = document.getElementById('thirdPartyList');

  if (!priv) {
    if (fpEl) fpEl.innerHTML = '<div class="empty" style="padding:12px 0"><div class="icon">⏳</div>Awaiting content analysis...</div>';
    if (trackerEl) trackerEl.innerHTML = '<div class="empty" style="padding:12px 0"><div class="icon">⏳</div>Awaiting tracker data...</div>';
    return;
  }

  const ps = priv.privacyScore ?? 100;
  if (numEl) {
    numEl.textContent = ps;
    numEl.style.color = ps >= 70 ? 'var(--accent-green)' : ps >= 40 ? 'var(--accent-orange)' : 'var(--accent-red)';
  }
  if (fillEl) {
    fillEl.style.width = ps + '%';
    fillEl.style.background = ps >= 70 ? 'var(--accent-green)' : ps >= 40 ? 'var(--accent-orange)' : 'var(--accent-red)';
  }

  // Fingerprinting signals
  if (fpEl) {
    const fps = priv.fpSignals || [];
    if (fps.length === 0) {
      fpEl.innerHTML = makeIssueHTML('safe', '✅', 'No Fingerprinting Detected', 'No browser fingerprinting signals found on this page');
    } else {
      fpEl.innerHTML = fps.map(f =>
        makeIssueHTML('warning', '🖐️', 'Fingerprinting Signal', f)
      ).join('');
    }
  }

  // Trackers
  if (trackerEl) {
    const trackers = priv.trackers;
    if (!trackers || trackers.total === 0) {
      trackerEl.innerHTML = '<div class="empty" style="padding:14px 0"><div class="icon">🎉</div>No trackers detected!<div class="sub">This page appears clean of trackers</div></div>';
    } else {
      const cats = [
        { key: 'advertising', label: '📢 Advertising', color: 'var(--accent-red)' },
        { key: 'analytics', label: '📊 Analytics', color: 'var(--accent-blue)' },
        { key: 'social', label: '👥 Social', color: 'var(--accent-purple)' },
        { key: 'fingerprinting', label: '🖐️ Fingerprinting', color: 'var(--accent-orange)' },
        { key: 'other', label: '🔮 Other', color: 'var(--text-muted)' },
      ];
      trackerEl.innerHTML = cats
        .filter(c => (trackers[c.key] || []).length > 0)
        .map(c => {
          const list = trackers[c.key];
          return `
            <div class="tracker-category">
              <div class="tracker-header">
                <span class="tracker-name" style="color:${c.color}">${c.label}</span>
                <span class="tracker-count">${list.length} found</span>
              </div>
              <div class="tracker-list">
                ${list.map(d => `<span class="tracker-tag">${esc(d)}</span>`).join('')}
              </div>
            </div>
          `;
        }).join('');
    }
  }

  // Third party
  if (thirdEl) {
    const count = priv.thirdPartyScripts ?? 0;
    thirdEl.innerHTML = `
      <div class="js-item">
        <div class="label"><span>🌐</span>Third-Party Scripts</div>
        <span class="badge ${count > 10 ? 'bad' : count > 3 ? 'warn' : 'ok'}">${count}</span>
      </div>
    `;
  }
}

// ---- Load Cookies ----
function loadCookies() {
  chrome.runtime.sendMessage({ type: 'GET_COOKIES' }, (resp) => {
    if (chrome.runtime.lastError) {
      document.getElementById('cookieList').innerHTML = '<div class="empty"><div class="icon">❌</div>Failed to load cookies</div>';
      return;
    }
    const data = resp?.data;
    if (!data) {
      document.getElementById('cookieList').innerHTML = '<div class="empty"><div class="icon">🍪</div>No cookie data available</div>';
      return;
    }

    // Update cookie stat
    document.getElementById('stat-cookies').textContent = data.total;

    const statsEl = document.getElementById('cookieStats');
    if (statsEl) {
      statsEl.innerHTML = `
        <div class="stats-grid" style="margin-bottom:10px">
          <div class="stat-card"><div class="stat-icon">📋</div><div><div class="stat-value">${data.total}</div><div class="stat-name">Total</div></div></div>
          <div class="stat-card"><div class="stat-icon">⏱️</div><div><div class="stat-value">${data.session.length}</div><div class="stat-name">Session</div></div></div>
          <div class="stat-card"><div class="stat-icon">💾</div><div><div class="stat-value">${data.persistent.length}</div><div class="stat-name">Persistent</div></div></div>
          <div class="stat-card"><div class="stat-icon">🔒</div><div><div class="stat-value" style="color:var(--accent-green)">${data.secure.length}</div><div class="stat-name">Secure</div></div></div>
          <div class="stat-card"><div class="stat-icon">🕵️</div><div><div class="stat-value" style="color:${data.tracking.length>0?'var(--accent-red)':'var(--accent-green)'}">${data.tracking.length}</div><div class="stat-name">Tracking</div></div></div>
          <div class="stat-card"><div class="stat-icon">⚠️</div><div><div class="stat-value" style="color:${data.insecure.length>0?'var(--accent-orange)':'var(--accent-green)'}">${data.insecure.length}</div><div class="stat-name">Insecure</div></div></div>
        </div>
      `;
    }

    const listEl = document.getElementById('cookieList');
    if (!listEl) return;

    // Merge: tracking first, then session, then persistent
    const tracking = data.tracking.map(c => ({ ...c, _type: 'tracking' }));
    const trackingNames = new Set(tracking.map(c => c.name + c.domain));
    const session = data.session.filter(c => !trackingNames.has(c.name + c.domain)).map(c => ({ ...c, _type: 'session' }));
    const persistent = data.persistent.filter(c => !trackingNames.has(c.name + c.domain)).map(c => ({ ...c, _type: 'persistent' }));
    const all = [...tracking, ...session, ...persistent];

    if (all.length === 0) {
      listEl.innerHTML = '<div class="empty"><div class="icon">🍪</div>No cookies found on this page</div>';
      return;
    }

    listEl.innerHTML = all.slice(0, 40).map(cookie => {
      const tags = [`<span class="cookie-tag ${cookie._type}">${cookie._type}</span>`];
      if (cookie.secure) tags.push('<span class="cookie-tag secure">secure</span>');
      if (cookie.httpOnly) tags.push('<span class="cookie-tag httponly">httponly</span>');
      return `
        <div class="cookie-item">
          <div class="cookie-name">${esc(cookie.name)}</div>
          <div class="cookie-meta">
            <span>${esc(cookie.domain || '—')}</span>
            ${tags.join('')}
            ${cookie.expirationDate ? `<span>Expires: ${new Date(cookie.expirationDate * 1000).toLocaleDateString()}</span>` : ''}
          </div>
        </div>
      `;
    }).join('');

    if (all.length > 40) {
      listEl.innerHTML += `<div class="empty" style="padding:8px 0">… and ${all.length - 40} more cookies</div>`;
    }
  });
}

function loadCookieCount(data) {
  chrome.runtime.sendMessage({ type: 'GET_COOKIES' }, (resp) => {
    if (resp?.data) {
      document.getElementById('stat-cookies').textContent = resp.data.total;
    }
  });
}

// ---- Load Extensions ----
function loadExtensions() {
  const el = document.getElementById('extensionList');
  if (!el) return;
  el.innerHTML = '<div class="empty"><div class="icon">⏳</div>Loading extensions...</div>';

  chrome.runtime.sendMessage({ type: 'GET_EXTENSIONS' }, (resp) => {
    if (chrome.runtime.lastError) {
      el.innerHTML = '<div class="empty"><div class="icon">❌</div>Failed to load extensions</div>';
      return;
    }
    const extensions = resp?.data;
    if (!extensions?.length) {
      el.innerHTML = '<div class="empty"><div class="icon">🔌</div>No extensions found</div>';
      return;
    }

    el.innerHTML = extensions
      .sort((a, b) => b.riskScore - a.riskScore)
      .map(ext => {
        const highRisk = ext.permissions.filter(p =>
          ['<all_urls>', 'tabs', 'cookies', 'webRequest', 'clipboardRead', 'nativeMessaging', 'debugger', 'management', 'proxy'].includes(p)
        );
        const other = ext.permissions.filter(p => !highRisk.includes(p));

        return `
          <div class="ext-item">
            <div class="ext-header">
              <span class="ext-name">${esc(ext.name)}</span>
              <span class="risk-badge risk-${ext.riskLevel}">${ext.riskLevel} RISK</span>
            </div>
            <div class="ext-meta">v${esc(ext.version)} · ${esc(ext.installType)} · ${ext.enabled ? '✓ Enabled' : '○ Disabled'}</div>
            <div class="ext-perms">
              ${highRisk.map(p => `<span class="perm-tag high">${esc(p)}</span>`).join('')}
              ${other.slice(0, 8).map(p => `<span class="perm-tag">${esc(p)}</span>`).join('')}
              ${other.length > 8 ? `<span class="perm-tag">+${other.length - 8} more</span>` : ''}
            </div>
            ${ext.risks.length > 0 ? `<div class="ext-risk-note">⚠ ${esc(ext.risks[0])}</div>` : ''}
          </div>
        `;
      }).join('');
  });
}

// ---- Alerts ----
function addAlert(level, title, desc, extra) {
  // Deduplicate per tab
  const existing = alertsLog.find(a => a.title === title);
  if (existing) {
    existing.time = new Date().toLocaleTimeString();
    return;
  }
  alertsLog.unshift({ level, title, desc, extra: extra || '', time: new Date().toLocaleTimeString() });
  if (alertsLog.length > 50) alertsLog.pop();
}

function clearAlerts() {
  alertsLog.length = 0;
  renderAlerts();
}

function renderAlerts() {
  const el = document.getElementById('alertsList');
  if (!el) return;

  if (!alertsLog.length) {
    el.innerHTML = '<div class="empty"><div class="icon">🔕</div>No alerts yet<div class="sub">Alerts appear as pages are scanned</div></div>';
    return;
  }

  el.innerHTML = alertsLog.map(a => `
    <div class="alert-item ${a.level}">
      <div class="alert-icon">${a.level === 'safe' ? '🟢' : a.level === 'warn' ? '🟡' : '🔴'}</div>
      <div>
        <div class="alert-title">${esc(a.title)}</div>
        <div class="alert-desc">${esc(a.desc)}${a.extra ? ` — ${esc(a.extra)}` : ''}</div>
        <div class="alert-time">${a.time}</div>
      </div>
    </div>
  `).join('');
}

// ---- Rescan ----
function rescan() {
  const btn = document.getElementById('scanBtn');
  btn.textContent = '⟳ Scanning...';
  btn.classList.add('scanning');
  btn.disabled = true;
  showScanningState();

  chrome.runtime.sendMessage({ type: 'SCAN_NOW' }, (resp) => {
    btn.textContent = '↻ Rescan';
    btn.classList.remove('scanning');
    btn.disabled = false;

    if (resp?.data) {
      currentData = resp.data;
      renderAll(resp.data);
    } else {
      // Retry load
      setTimeout(loadData, 500);
    }
  });
}

// ---- Generate Report ----
function generateReport() {
  if (!currentData) {
    alert('No scan data available. Please wait for the page to scan.');
    return;
  }

  const d = currentData;
  const trust = d.trustLevel || getTrustLevel(d.finalScore);
  const now = new Date().toLocaleString();
  const issues = d.urlIssues || [];
  const cd = d.contentData || {};
  const jd = d.jsData || {};
  const priv = d.privacyData || cd;

  const lines = [
    `=================================================================`,
    `            SENTINEL SHIELD v2.0 — SECURITY REPORT`,
    `           Developed by Hardik · poop Organization India`,
    `=================================================================`,
    `Generated : ${now}`,
    `URL       : ${d.url}`,
    `Domain    : ${d.hostname}`,
    ``,
    `TRUST SCORE: ${d.finalScore} / 100 — ${trust.level} ${trust.emoji}`,
    d.isKnownSafe ? `Status: Recognized as a known trusted domain` : `Score based on URL, content & behavior analysis`,
    ``,
    `-----------------------------------------------------------------`,
    `CONNECTION SECURITY`,
    `-----------------------------------------------------------------`,
    `Protocol    : ${d.isHTTPS ? 'HTTPS (Encrypted)' : 'HTTP (UNENCRYPTED — HIGH RISK)'}`,
    `Certificate : ${d.isHTTPS ? 'SSL/TLS Present' : 'NONE'}`,
    ``,
    `-----------------------------------------------------------------`,
    `URL ANALYSIS (${issues.length} findings)`,
    `-----------------------------------------------------------------`,
    ...(issues.length ? issues.map(i => `[${i.type.toUpperCase().padEnd(7)}] ${i.msg}`) : ['No URL-level issues detected.']),
    ``,
    `-----------------------------------------------------------------`,
    `SCAM & CONTENT DETECTION`,
    `-----------------------------------------------------------------`,
    `Scam Types Detected  : ${cd.scamTypes?.length ? cd.scamTypes.join(', ') : 'None'}`,
    `Fake Login Form      : ${cd.hasFakeLogin ? '⚠ YES — HIGH RISK' : '✓ No'}`,
    `Hidden Forms         : ${cd.hasHiddenForms ? '⚠ YES' : '✓ No'}`,
    `Credential Harvesting: ${cd.hasCredentialHarvesting ? '⚠ YES — HIGH RISK' : '✓ No'}`,
    `Clipboard Hijacking  : ${cd.hasClipboardHijack ? '⚠ YES' : '✓ No'}`,
    `Bank Impersonation   : ${cd.hasBankImpersonation ? '⚠ YES — HIGH RISK' : '✓ No'}`,
    `Gov Impersonation    : ${cd.hasGovImpersonation ? '⚠ YES' : '✓ No'}`,
    `Tech Support Scam    : ${cd.hasSupportScam ? '⚠ YES' : '✓ No'}`,
    `Crypto Scam          : ${cd.hasCryptoScam ? '⚠ YES' : '✓ No'}`,
    `Total Forms          : ${cd.formCount ?? 'N/A'}`,
    ``,
    `-----------------------------------------------------------------`,
    `JAVASCRIPT BEHAVIOR`,
    `-----------------------------------------------------------------`,
    `eval() Usage         : ${jd.hasEval ? '⚠ YES' : '✓ No'}`,
    `Code Obfuscation     : ${jd.hasObfuscation ? '⚠ YES' : '✓ No'}`,
    `Crypto Miner         : ${jd.hasCryptoMiner ? '🔴 DETECTED' : '✓ No'}`,
    `Keylogger Pattern    : ${jd.hasKeylogger ? '🔴 DETECTED' : '✓ No'}`,
    `Credential Stealing  : ${jd.hasCredentialStealing ? '🔴 DETECTED' : '✓ No'}`,
    `Silent Redirect      : ${jd.hasSilentRedirect ? '⚠ YES' : '✓ No'}`,
    `Hidden Iframes       : ${jd.hasHiddenIframes ? '⚠ YES' : '✓ No'}`,
    `DOM Attack Pattern   : ${jd.hasDomManipulationAttack ? '⚠ YES' : '✓ No'}`,
    `Total Scripts        : ${jd.scriptCount ?? 'N/A'}`,
    `Inline Scripts       : ${jd.inlineScriptCount ?? 'N/A'}`,
    `External Scripts     : ${jd.externalScriptCount ?? 'N/A'}`,
    jd.obfuscationSigns?.length ? `Obfuscation Signs    : ${jd.obfuscationSigns.join('; ')}` : '',
    jd.cryptoMinerSigns?.length ? `Miner Signatures     : ${jd.cryptoMinerSigns.join('; ')}` : '',
    ``,
    `-----------------------------------------------------------------`,
    `PRIVACY ANALYSIS`,
    `-----------------------------------------------------------------`,
    `Privacy Score        : ${priv.privacyScore ?? 'N/A'} / 100`,
    `Total Trackers       : ${priv.trackers?.total ?? 0}`,
    `  • Advertising      : ${priv.trackers?.advertising?.length ?? 0}`,
    `  • Analytics        : ${priv.trackers?.analytics?.length ?? 0}`,
    `  • Social           : ${priv.trackers?.social?.length ?? 0}`,
    `  • Fingerprinting   : ${priv.trackers?.fingerprinting?.length ?? 0}`,
    `  • Other            : ${priv.trackers?.other?.length ?? 0}`,
    `Fingerprint Signals  : ${priv.fpSignals?.join(', ') || 'None'}`,
    `Third-Party Scripts  : ${priv.thirdPartyScripts ?? 'N/A'}`,
    ``,
    `-----------------------------------------------------------------`,
    `RECOMMENDATIONS`,
    `-----------------------------------------------------------------`,
    ...generateRecommendations(d),
    ``,
    `=================================================================`,
    `   Sentinel Shield v2.0 — by Hardik · poop Organization India`,
    `   GitHub: https://github.com/ewwhardik`,
    `   Web: https://poop.org.in`,
    `=================================================================`,
  ].filter(l => l !== null);

  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sentinel-report-${d.hostname}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

function generateRecommendations(data) {
  const recs = [];
  if (!data.isHTTPS) recs.push('• CRITICAL: Do NOT enter any passwords — connection is unencrypted (HTTP)');
  if (data.finalScore < 35) recs.push('• CRITICAL: Leave this site immediately — multiple high-severity threats detected');
  else if (data.finalScore < 60) recs.push('• Caution: Proceed carefully — suspicious patterns detected');
  if (data.contentData?.hasFakeLogin) recs.push('• Do NOT enter any credentials on this page');
  if (data.contentData?.hasCryptoScam) recs.push('• This is a crypto scam — do NOT send any cryptocurrency');
  if (data.contentData?.hasClipboardHijack) recs.push('• Verify clipboard contents before pasting (e.g. crypto wallet addresses may be swapped)');
  if (data.jsData?.hasCryptoMiner) recs.push('• This page is mining cryptocurrency using your CPU — close the tab immediately');
  if (data.jsData?.hasKeylogger) recs.push('• Possible keylogger — do NOT type any sensitive information');
  if (data.contentData?.trackers?.total > 10) recs.push('• High tracker count — consider using uBlock Origin or Privacy Badger');
  if (data.urlIssues?.some(i => i.type === 'danger' && i.msg.includes('typosquat'))) recs.push('• Possible fake website — double-check the URL before proceeding');
  if (recs.length === 0) recs.push('• No immediate threats — continue with normal caution');
  return recs;
}

// ---- Helpers ----
function getTrustLevel(score) {
  if (score >= 80) return { level: 'SAFE', color: '#00f096', emoji: '🟢' };
  if (score >= 60) return { level: 'LOW RISK', color: '#f59e0b', emoji: '🟡' };
  if (score >= 35) return { level: 'SUSPICIOUS', color: '#f97316', emoji: '🟠' };
  return { level: 'DANGEROUS', color: '#ef4444', emoji: '🔴' };
}

function updateScoreCircle(score, trust) {
  const circumference = 182.2;
  const offset = circumference - (score / 100) * circumference;
  const fill = document.getElementById('scoreFill');
  if (fill) {
    fill.style.strokeDashoffset = offset;
    fill.style.stroke = trust.color;
  }
  const num = document.getElementById('scoreNum');
  if (num) {
    num.textContent = score;
    num.style.color = trust.color;
  }
}

function updateMeter(score) {
  const cursor = document.getElementById('meterCursor');
  if (cursor) cursor.style.left = Math.max(2, Math.min(98, score)) + '%';
}

function createIssueItem(issue) {
  const div = document.createElement('div');
  const t = issue.type === 'danger' ? 'danger' : issue.type === 'warning' ? 'warning' : issue.type === 'info' ? 'info' : 'safe';
  const icon = issue.type === 'danger' ? '🔴' : issue.type === 'warning' ? '🟡' : issue.type === 'info' ? 'ℹ️' : '🟢';
  div.className = `issue-item ${t}`;
  div.innerHTML = `<span class="issue-icon">${icon}</span><div class="issue-text">${esc(issue.msg)}</div>`;
  return div;
}

function makeIssueHTML(type, icon, title, desc) {
  const cls = type === 'danger' ? 'danger' : type === 'warning' ? 'warning' : type === 'info' ? 'info' : 'safe';
  return `<div class="issue-item ${cls}">
    <span class="issue-icon">${icon}</span>
    <div class="issue-text"><strong>${esc(title)}</strong>${esc(desc)}</div>
  </div>`;
}

function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
  loadData();
  // Multiple retries to handle slow background startup
  setTimeout(loadData, 1000);
  setTimeout(loadData, 2500);
  setTimeout(loadData, 5000);
});
