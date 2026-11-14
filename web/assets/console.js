/* FaultSeeker++ console. Talks to the JSON API under /api; renders with textContent only (no innerHTML on data). */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const HASH_RE = /^0x[0-9a-fA-F]{64}$/;
  const FINAL = new Set(['completed', 'failed', 'cancelled', 'interrupted']);
  const BASE_TITLE = 'FaultSeeker | Transaction Forensics';
  const SUBMIT_HTML = 'Analyze transaction <span>→</span>';
  const FIELD_INPUT = {
    txn_hash: 'transaction', chain: 'chain', mode: 'model',
    model_key: 'model-key', rpc_url: 'rpc-url', rpc_key: 'rpc-key',
  };

  const state = {
    config: null, submitting: false,
    pollToken: 0, runId: null, run: null, e: 0, l: 0, skew: 0, failures: 0,
    sawRunning: false, tick: null, logLines: 0, stepperSig: '', previousView: 'setup',
    presetTimer: null,
  };

  /* ---------- helpers ---------- */
  function h(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class') n.className = v;
        else if (k === 'text') n.textContent = v;
        else if (k === 'dataset') Object.assign(n.dataset, v);
        else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return n;
  }

  function appendSafeMarkdownInline(parent, source) {
    const text = String(source ?? '');
    const token = /\*\*([^*\n]+)\*\*|(?<!\*)\*([^*\n]+)\*(?!\*)|`([^`\n]+)`/g;
    let offset = 0;
    let match;

    while ((match = token.exec(text)) !== null) {
      if (match.index > offset) {
        parent.append(document.createTextNode(text.slice(offset, match.index)));
      }

      let node;
      if (match[1] !== undefined) {
        node = document.createElement('strong');
        node.textContent = match[1];
      } else if (match[2] !== undefined) {
        node = document.createElement('em');
        node.textContent = match[2];
      } else {
        node = document.createElement('code');
        node.textContent = match[3];
      }

      parent.append(node);
      offset = token.lastIndex;
    }

    if (offset < text.length) {
      parent.append(document.createTextNode(text.slice(offset)));
    }
  }

  function safeMarkdown(source) {
    const root = document.createElement('div');
    root.className = 'safe-markdown';

    const text = String(source ?? '');
    if (!text.trim()) return root;

    const lines = text.replace(/\r\n?/g, '\n').split('\n');
    let paragraph = [];
    let list = null;

    function flushParagraph() {
      if (!paragraph.length) return;
      const p = document.createElement('p');
      appendSafeMarkdownInline(p, paragraph.join(' '));
      root.append(p);
      paragraph = [];
    }

    function endList() {
      list = null;
    }

    for (const line of lines) {
      const listMatch = /^\s*[-*]\s+(.+?)\s*$/.exec(line);

      if (listMatch) {
        flushParagraph();
        if (!list) {
          list = document.createElement('ul');
          root.append(list);
        }
        const item = document.createElement('li');
        appendSafeMarkdownInline(item, listMatch[1]);
        list.append(item);
        continue;
      }

      if (!line.trim()) {
        flushParagraph();
        endList();
        continue;
      }

      endList();
      paragraph.push(line.trim());
    }

    flushParagraph();
    return root;
  }
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const shortHash = (x) => (x && x.length > 20 ? `${x.slice(0, 10)}…${x.slice(-8)}` : x || '');
  const shortAddr = (x) => (x && x.length > 14 ? `${x.slice(0, 8)}…${x.slice(-6)}` : x || '');

  function fmtClock(sec) {
    sec = Math.max(0, Math.floor(sec));
    const hh = Math.floor(sec / 3600), mm = Math.floor((sec % 3600) / 60), ss = sec % 60;
    const p = (n) => String(n).padStart(2, '0');
    return hh ? `${hh}:${p(mm)}:${p(ss)}` : `${p(mm)}:${p(ss)}`;
  }
  function fmtDuration(sec) {
    if (sec == null || isNaN(sec)) return '—';
    sec = Math.round(sec);
    if (sec < 60) return `${sec}s`;
    return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  }
  function timeAgo(sec) {
    sec = Math.max(0, Math.floor(sec));
    if (sec < 5) return 'just now';
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
    if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
    return `${Math.floor(sec / 86400)}d ago`;
  }
  const serverNow = () => Date.now() / 1000 + state.skew;
  function fmtDate(value) {
    const d = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
    return isNaN(d) ? String(value || '—') : d.toLocaleString();
  }
  const chainInfo = (id) => (state.config && state.config.chains.find((c) => c.id === id)) || null;
  const chainLabel = (id) => (chainInfo(id) ? chainInfo(id).label : (id || '—'));
  const modelInfo = (id) => (state.config && state.config.models.find((m) => m.id === id)) || null;

  async function api(path, opts = {}) {
    const init = { method: opts.method || 'GET', cache: 'no-store' };
    if (opts.body !== undefined) {
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(opts.body);
    }
    const res = await fetch(path, init);
    if (res.status === 401) {
      // Session missing or expired: go to the sign-in page and stop this flow (the page is navigating away).
      let code = null;
      try { code = (await res.clone().json()).error.code; } catch (_) { /* not our JSON */ }
      if (code === 'auth_required') { window.location.assign('/login'); await new Promise(() => {}); }
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    return { ok: res.ok, status: res.status, data };
  }

  /* ---------- notice ---------- */
  let noticeTimer = null;
  function notify(message, opts = {}) {
    const box = $('notice');
    clearTimeout(noticeTimer);
    clear(box);
    box.dataset.kind = opts.kind || 'info';
    const actions = h('div', { class: 'notice-actions' });
    for (const a of opts.actions || []) {
      actions.append(h('button', { type: 'button', class: 'secondary', onclick: a.onClick, text: a.label }));
    }
    actions.append(h('button', { type: 'button', class: 'quiet', onclick: hideNotice, 'aria-label': 'Dismiss message', text: 'Dismiss' }));
    const text = h('div', { class: 'notice-text' }, message);
    if (opts.detail) text.append(h('div', { class: 'hint', text: opts.detail }));
    box.append(text, actions);
    box.hidden = false;
    if ((opts.kind || 'info') === 'info' && !opts.sticky) noticeTimer = setTimeout(hideNotice, 9000);
  }
  function hideNotice() { const box = $('notice'); clearTimeout(noticeTimer); box.hidden = true; clear(box); }

  /* ---------- views & routing ---------- */
  const VIEWS = ['setup', 'running', 'results', 'history'];
  let currentView = 'setup';
  function showView(name, { focus = true } = {}) {
    state.previousView = currentView;
    currentView = name;
    for (const v of VIEWS) $(v).hidden = v !== name;
    window.scrollTo(0, 0);
    if (focus) {
      const target = $(name).querySelector('h1');
      if (target) { target.setAttribute('tabindex', '-1'); target.focus({ preventScroll: true }); }
    }
  }

  function route(initial = false) {
    state.pollToken++;                 // stops any running poll loop
    clearInterval(state.tick);
    const [name, arg] = location.hash.replace(/^#/, '').split('/');
    document.title = BASE_TITLE;
    if (name === 'run' && arg) return showRun(arg);
    if (name === 'result' && arg) return showResult(arg);
    if (name === 'capture') return showCapture();
    if (name === 'history') return showHistory();
    showView('setup', { focus: !initial });
    refreshRecent();
  }

  /* ---------- config & form ---------- */
  async function loadConfig() {
    try {
      const r = await api('/api/config');
      if (!r.ok) throw new Error('config');
      state.config = r.data;
      applyConfig();
      return true;
    } catch (_) {
      setEnvironment('OFFLINE', 'bad', 'The server could not be reached.');
      notify('Could not reach the FaultSeeker service.', {
        kind: 'error', actions: [{ label: 'Retry', onClick: async () => { hideNotice(); if (await loadConfig()) route(true); } }],
      });
      return false;
    }
  }

  function setEnvironment(label, tone, title) {
    const badge = $('environment');
    badge.textContent = label;
    badge.dataset.state = tone;
    badge.title = title || '';
  }

  function applyConfig() {
    const cfg = state.config;
    const env = cfg.environment;
    setEnvironment(`${env.host.toUpperCase()} · ${env.ready ? 'READY' : 'ATTENTION'}`, env.ready ? 'ok' : 'warn',
      env.ready ? 'Replay, source download and explorer tools are available.' : env.issues.join(' '));
    if (cfg.auth && cfg.auth.required) addSignOut();
    if (env.ready && env.notes && env.notes.length) notify(env.notes.join(' '), { kind: 'info' });
    if (!env.ready) notify('This deployment is missing tools needed for analysis.', { kind: 'warn', detail: env.issues.join(' '), sticky: true });

    const chain = $('chain');
    clear(chain);
    for (const c of cfg.chains) {
      const tag = { beta: ' (beta)', partial: ' (partial)', unsupported: ' (not supported)' }[c.support] || '';
      chain.append(h('option', { value: c.id, text: c.label + tag, disabled: c.support === 'unsupported', title: c.note || null }));
    }

    const model = $('model');
    clear(model);
    for (const m of cfg.models) {
      const opt = h('option', { value: m.id, text: m.label });
      if (m.default) opt.selected = true;
      model.append(opt);
    }
    buildPresets();
    buildDatalist();
    updateKeyRequirement();
    validateForm();
  }

  function addSignOut() {
    if ($('signout')) return;
    const button = h('button', { id: 'signout', type: 'button', class: 'quiet', text: 'Sign out', onclick: async () => {
      try { await fetch('/auth/logout', { method: 'POST', cache: 'no-store' }); } catch (_) { /* leave anyway */ }
      window.location.assign('/login');
    } });
    document.querySelector('.header-actions').append(button);
  }

  function refreshRecent() {
    if (!state.config) return;
    api('/api/config').then((r) => {
      if (r.ok) { state.config.recent = r.data.recent; state.config.active_run = r.data.active_run; buildDatalist(); }
    }).catch(() => {});
  }

  function buildDatalist() {
    const list = $('tx-presets');
    clear(list);
    const seen = new Set();
    for (const r of state.config.recent || []) {
      if (seen.has(r.hash)) continue;
      seen.add(r.hash);
      list.append(h('option', { value: r.hash, label: `Replay · ${r.chain ? chainLabel(r.chain) : 'cached'}` }));
    }
    for (const chain of Object.keys(state.config.presets)) {
      for (const p of state.config.presets[chain]) {
        if (seen.has(p.hash)) continue;
        seen.add(p.hash);
        list.append(h('option', { value: p.hash, label: `${p.name} · ${chainLabel(chain)}` }));
      }
    }
  }

  /* presets */
  function buildPresets() {
    for (const chain of ['eth', 'bsc']) {
      const box = $(`preset-list-${chain}`);
      if (!box) continue;
      clear(box);
      const items = (state.config.presets[chain] || []);
      if (!items.length) { box.append(h('p', { class: 'preset-empty', text: 'No verified presets for this network.' })); continue; }
      for (const p of items) {
        const meta = [p.date, p.lost].filter(Boolean).join(' · ');
        box.append(h('button', {
          type: 'button', class: 'preset-item', onclick: () => pickPreset(chain, p.hash),
        }, h('strong', { text: p.name }), meta && h('span', { class: 'meta', text: meta }),
        p.cause && h('span', { class: 'cause', text: p.cause })));
      }
    }
  }
  function setPreset(chain, open) {
    const btn = $(`preset-btn-${chain}`), box = $(`preset-list-${chain}`);
    if (!btn || !box) return;
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    box.hidden = !open;
  }
  function closePresets(except) { for (const c of ['eth', 'bsc']) if (c !== except) setPreset(c, false); }
  function pickPreset(chain, hash) {
    $('transaction').value = hash;
    $('chain').value = chain;
    setFieldError('transaction', '');
    closePresets();
    validateForm();
    ($('model-key').disabled ? $('analyze') : $('model-key')).focus();
  }

  /* key requirement */
  function selectedModel() { return modelInfo($('model').value); }
  function updateKeyRequirement() {
    const m = selectedModel();
    const input = $('model-key');
    const who = m ? m.provider_label : 'the selected provider';
    const stored = 'The key is used for this request only, is sent only to ' + who + ', and is never saved in browser storage.';
    let tag = '', hint = stored;
    if (!m) { tag = ''; }
    else if (m.key_required) { tag = '· Required'; hint = `Key for ${who}. ${stored}`; }
    else if (m.key_optional) { tag = '· Optional'; hint = `Leave blank to use the server's ${who} key, or enter your own. ${stored}`; }
    else { tag = '· Not needed'; hint = `${who} does not use an API key from this form.`; }
    $('key-requirement').textContent = tag;
    $('key-hint').textContent = hint;
    input.disabled = !!m && !m.key_required && !m.key_optional;
    if (input.disabled) input.value = '';
    $('show-key').disabled = input.disabled;
  }

  function validateForm() {
    const m = selectedModel();
    const hashOk = HASH_RE.test($('transaction').value.trim());
    const keyOk = !m || !m.key_required || $('model-key').value.trim().length > 0;
    $('analyze').disabled = state.submitting || !(state.config && m && hashOk && keyOk && $('chain').value);
  }

  function setFieldError(inputId, message) {
    const input = $(inputId);
    const holder = input.closest('.input-action') || input;
    const existing = holder.parentNode.querySelector(`.field-error[data-for="${inputId}"]`);
    if (existing) existing.remove();
    input.removeAttribute('aria-invalid');
    if (!message) return;
    input.setAttribute('aria-invalid', 'true');
    holder.insertAdjacentElement('afterend', h('p', { class: 'field-error', role: 'alert', dataset: { for: inputId }, text: message }));
  }
  function clearFieldErrors() { for (const id of Object.values(FIELD_INPUT)) setFieldError(id, ''); }

  async function submit(event) {
    event.preventDefault();
    if (state.submitting || $('analyze').disabled) return;
    clearFieldErrors();
    hideNotice();
    const payload = {
      txn_hash: $('transaction').value.trim(), chain: $('chain').value, mode: $('model').value,
      model_key: $('model-key').value.trim(), rpc_url: $('rpc-url').value.trim(), rpc_key: $('rpc-key').value.trim(),
    };
    state.submitting = true;
    $('analyze').textContent = 'Starting…';
    validateForm();
    try {
      const r = await api('/api/runs', { method: 'POST', body: payload });
      if (r.status === 201) { location.hash = `#run/${r.data.id}`; return; }
      handleSubmitError(r);
    } catch (_) {
      notify('Could not reach the FaultSeeker service. Check your connection and try again.', { kind: 'error' });
    } finally {
      state.submitting = false;
      $('analyze').innerHTML = SUBMIT_HTML;
      validateForm();
    }
  }

  function handleSubmitError(r) {
    const err = (r.data && r.data.error) || { message: `Request failed (${r.status}).` };
    if (err.code === 'busy') {
      notify(err.message, { kind: 'warn', sticky: true, actions: err.active_run ? [{ label: 'Open running analysis', onClick: () => { location.hash = `#run/${err.active_run}`; } }] : [] });
      return;
    }
    if (err.code === 'key_validation_unavailable') {
      notify('Could not verify the API key right now, so the analysis was not started.', { kind: 'warn', sticky: true, detail: err.message });
      return;
    }
    if (err.code === 'server_key_rejected') {
      notify(err.message, { kind: 'error', sticky: true });
      return;
    }
    if (err.code === 'environment_not_ready') {
      notify(err.message, { kind: 'error', detail: (err.issues || []).join(' ') });
      return;
    }
    const target = FIELD_INPUT[err.field];
    if (target) {
      if (target.startsWith('rpc')) $('analysis-form').querySelector('details.rpc').open = true;
      setFieldError(target, err.message);
      $(target).focus();
    } else {
      notify(err.message, { kind: 'error' });
    }
  }

  /* ---------- running view ---------- */
  function resetRunView(id) {
    state.runId = id; state.run = null; state.e = 0; state.l = 0; state.failures = 0;
    state.sawRunning = false; state.logLines = 0; state.stepperSig = '';
    clear($('stepper')); clear($('activity')); clear($('run-details'));
    $('logs').textContent = ''; $('log-count').textContent = '0 lines';
    $('activity-empty').hidden = false;
    $('run-kind-label').textContent = 'LIVE INVESTIGATION';
    $('run-title').textContent = 'Analyzing transaction';
    $('active-task').textContent = 'Connecting to the pipeline';
    $('active-description').textContent = 'Waiting for the first confirmed progress event.';
    $('elapsed').textContent = '00:00'; $('last-activity').textContent = 'Waiting';
    const panel = document.querySelector('.active-panel');
    for (const x of panel.querySelectorAll('.error-detail, .error-actions')) x.remove();
    $('cancel').hidden = false; $('cancel').disabled = false; $('cancel').textContent = 'Cancel run';
    $('running').dataset.state = 'running';
    document.querySelector('.running-badge').textContent = 'IN PROGRESS';
    setConnection('live', 'Connecting');
  }

  function setConnection(mode, text) {
    const dot = document.querySelector('.activity-line .pulse');
    dot.dataset.state = mode === 'live' ? '' : mode;
    if (!mode || mode === 'live') delete dot.dataset.state;
    $('connection').textContent = text || (mode === 'offline' ? 'Reconnecting…' : mode === 'idle' ? 'Finished' : 'Live');
  }

  async function showRun(id) {
    showView('running');
    resetRunView(id);
    const token = ++state.pollToken;
    while (state.pollToken === token) {
      let wait = 1000;
      try {
        const r = await api(`/api/runs/${id}?e=${state.e}&l=${state.l}`);
        if (state.pollToken !== token) return;
        if (r.status === 404) { notify('That run no longer exists.', { kind: 'error' }); location.hash = ''; return; }
        if (!r.ok) throw new Error('poll');
        state.failures = 0;
        const done = applyRun(r.data);
        if (done === 'redirect') return;
        if (done) return;
      } catch (_) {
        state.failures++;
        setConnection('offline');
        wait = Math.min(1000 * 2 ** Math.min(state.failures, 3), 8000);
        if (state.failures === 20) notify('Still unable to reach the service. The analysis keeps running on the server; this page will resume when the connection returns.', { kind: 'warn' });
      }
      await sleep(wait);
    }
  }

  const BADGE = { running: 'IN PROGRESS', completed: 'COMPLETE', failed: 'FAILED', cancelled: 'CANCELLED', interrupted: 'INTERRUPTED' };

  function applyRun(data) {
    const run = data.run;
    state.skew = data.server_time - Date.now() / 1000;
    state.run = run;
    if (run.state === 'running') state.sawRunning = true;

    if (run.state === 'completed' && !state.sawRunning) { location.replace(`#result/${run.id}`); return 'redirect'; }

    $('run-title').textContent = `Analyzing ${shortHash(run.txn_hash)}`;
    document.title = `${run.state === 'running' ? 'Analyzing' : 'Run'} ${shortHash(run.txn_hash)} | FaultSeeker`;
    $('running').dataset.state = run.state;
    document.querySelector('.running-badge').textContent = BADGE[run.state] || run.state.toUpperCase();
    $('active-task').textContent = run.current.title;
    $('active-description').textContent = run.current.description;
    renderStepper(run.stages);
    renderDetails(run);
    appendEvents(data.events);
    appendLogs(data.logs);
    state.e = data.event_cursor;
    state.l = data.log_cursor;
    setConnection(run.state === 'running' ? 'live' : 'idle', run.state === 'running' ? 'Live' : 'Finished');
    updateTiming();
    clearInterval(state.tick);

    if (run.state === 'running') {
      state.tick = setInterval(updateTiming, 1000);
      return false;
    }
    $('cancel').hidden = true;
    if (run.state === 'completed') {
      setTimeout(() => { if (state.runId === run.id && location.hash === `#run/${run.id}`) location.hash = `#result/${run.id}`; }, 700);
      return true;
    }
    renderFailure(run);
    return true;
  }

  function renderStepper(stages) {
    const sig = JSON.stringify(stages);
    if (sig === state.stepperSig) return;
    state.stepperSig = sig;
    const list = $('stepper');
    clear(list);
    const words = { pending: 'Waiting', active: 'In progress', done: 'Complete', failed: 'Failed' };
    for (const s of stages) {
      list.append(h('li', { class: 'step', dataset: { status: s.status }, 'aria-current': s.status === 'active' ? 'step' : null },
        h('span', { class: 'step-marker', 'aria-hidden': 'true' }),
        h('span', { class: 'step-label', text: s.label }),
        h('span', { class: 'step-state', text: words[s.status] || s.status })));
    }
  }

  function renderDetails(run) {
    const dl = $('run-details');
    clear(dl);
    const m = modelInfo(run.model);
    const rows = [
      ['Transaction', shortHash(run.txn_hash), run.txn_hash],
      ['Network', chainLabel(run.chain)],
      ['Model', m ? m.label : run.model],
      ['Provider', m ? m.provider_label : (run.provider || '—')],
      ['RPC', run.rpc_mode === 'custom' ? 'Custom endpoint' : 'Server connection'],
      ['Model key', run.key_source === 'user' ? 'Supplied for this run' : run.key_source === 'server' ? 'Server key' : 'Not used'],
      ['Run ID', run.id],
    ];
    for (const [k, v, title] of rows) dl.append(h('dt', { text: k }), h('dd', { text: v, title }));
  }

  function updateTiming() {
    const run = state.run;
    if (!run) return;
    const end = run.finished_at || serverNow();
    $('elapsed').textContent = fmtClock(end - run.created_at);
    $('last-activity').textContent = run.state === 'running' ? timeAgo(serverNow() - run.last_activity_at)
      : (run.finished_at ? fmtDate(run.finished_at) : '—');
  }

  function appendEvents(events) {
    if (!events.length) return;
    const list = $('activity');
    for (const ev of events) {
      list.prepend(h('li', { dataset: { level: ev.level } },
        h('time', { datetime: new Date(ev.ts * 1000).toISOString(), text: new Date(ev.ts * 1000).toLocaleTimeString([], { hour12: false }) }),
        h('span', { text: ev.message })));
    }
    while (list.children.length > 60) list.lastChild.remove();
    $('activity-empty').hidden = true;
  }

  function appendLogs(lines) {
    if (!lines.length) return;
    const pre = $('logs');
    const stick = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
    pre.append(document.createTextNode(lines.join('\n') + '\n'));
    state.logLines += lines.length;
    if (pre.textContent.length > 600000) pre.textContent = pre.textContent.slice(-400000);
    $('log-count').textContent = `${state.logLines} ${state.logLines === 1 ? 'line' : 'lines'}`;
    if (stick) pre.scrollTop = pre.scrollHeight;
  }

  function renderFailure(run) {
    const panel = document.querySelector('.active-panel');
    for (const x of panel.querySelectorAll('.error-detail, .error-actions')) x.remove();
    const err = run.error;
    if (err) {
      panel.append(h('div', { class: 'error-detail', role: 'alert' },
        h('strong', { text: err.message }), err.hint && h('span', { text: err.hint })));
    }
    panel.append(h('div', { class: 'error-actions' },
      h('button', { type: 'button', class: 'primary', onclick: () => { location.hash = ''; }, text: 'Back to setup' }),
      h('button', { type: 'button', class: 'secondary', onclick: () => { const d = document.querySelector('details.technical'); d.open = true; d.scrollIntoView({ behavior: 'smooth' }); }, text: 'View technical logs' })));
  }

  async function cancelRun() {
    if (!state.runId) return;
    if (!window.confirm('Cancel this analysis? Work in progress will be discarded.')) return;
    $('cancel').disabled = true;
    $('cancel').textContent = 'Cancelling…';
    try {
      const r = await api(`/api/runs/${state.runId}/cancel`, { method: 'POST' });
      if (!r.ok && r.status !== 409) notify((r.data && r.data.error && r.data.error.message) || 'Could not cancel the run.', { kind: 'error' });
    } catch (_) {
      notify('Could not reach the service to cancel the run.', { kind: 'error' });
      $('cancel').disabled = false; $('cancel').textContent = 'Cancel run';
    }
  }

  /* ---------- results ---------- */
  async function showResult(id) {
    showView('results');
    const box = $('results');
    clear(box);
    box.append(h('p', { class: 'hint', text: 'Loading report…' }));
    try {
      const r = await api(`/api/runs/${id}/result`);
      if (r.ok) { renderReport(r.data, { runId: id }); return; }
      const meta = await api(`/api/runs/${id}`);
      if (meta.ok && meta.data.run.state !== 'completed') { location.replace(`#run/${id}`); return; }
      notify((r.data && r.data.error && r.data.error.message) || 'This report is not available.', { kind: 'error' });
      location.hash = '';
    } catch (_) {
      clear(box);
      notify('Could not load the report.', { kind: 'error', actions: [{ label: 'Retry', onClick: () => showResult(id) }] });
    }
  }

  async function showCapture() {
    try {
      const r = await api('/api/capture');
      if (!r.ok) {
        notify((r.data && r.data.error && r.data.error.message) || 'No saved capture is available.', { kind: 'info' });
        location.hash = '';
        return;
      }
      showView('results');
      renderReport(r.data, { capture: true });
    } catch (_) {
      notify('Could not load the saved capture.', { kind: 'error' });
      location.hash = '';
    }
  }

  function explorerLink(kind, chain, value) {
    const info = chainInfo(chain);
    const base = info && (kind === 'tx' ? info.tx_url : info.address_url);
    if (!base) return h('span', { class: 'mono', text: value });
    return h('a', { href: base + value, target: '_blank', rel: 'noopener noreferrer', class: 'mono', text: kind === 'tx' ? shortHash(value) : shortAddr(value), title: value });
  }

  async function copy(text, button) {
    try { await navigator.clipboard.writeText(text); button.textContent = 'Copied'; }
    catch (_) { button.textContent = 'Press Ctrl+C'; }
    setTimeout(() => { button.textContent = 'Copy'; }, 1600);
  }

  function findingNode(f, chain, { top = false, rank } = {}) {
    const evidence = f.evidence || [];
    const node = h('li', { class: 'finding', dataset: { top: top ? 'true' : 'false' } },
      h('span', { class: 'rank', 'aria-label': `Rank ${rank}`, text: String(rank) }),
      h('div', null,
        h('h3', null, f.function, top && h('span', { class: 'pill tag', dataset: { tone: 'info' }, text: 'TOP SUSPECT' }),
          f.unranked && h('span', { class: 'pill tag', dataset: { tone: 'warn' }, text: 'UNRANKED' })),
        f.address && h('div', { class: 'addr' }, explorerLink('address', chain, f.address),
          h('button', { type: 'button', class: 'quiet', 'aria-label': `Copy address of ${f.function}`, onclick: (e) => copy(f.address, e.currentTarget), text: 'Copy' }))));
    if (evidence.length) {
      const d = h('details', { class: 'evidence' }, h('summary', { text: `Evidence (${evidence.length})` }),
        h('ul', null, evidence.map((x) => h('li', null, safeMarkdown(x)))));
      if (top) d.open = true;
      node.append(d);
    } else {
      node.append(h('p', { class: 'no-evidence', text: 'No evidence text was returned for this function.' }));
    }
    return node;
  }

  function renderReport(data, opts = {}) {
    const box = $('results');
    clear(box);
    const capture = data.kind === 'capture' || opts.capture;
    const chain = data.chain;
    const title = `${shortHash(data.transaction_hash)} on ${chainLabel(chain)}`;
    document.title = `Report ${shortHash(data.transaction_hash)} | FaultSeeker`;

    const actions = h('div', { class: 'actions' });
    if (opts.runId) {
      actions.append(h('a', { class: 'secondary', href: `/api/runs/${opts.runId}/result?download=raw`, download: '', text: 'Download JSON' }));
    } else if (capture) {
      actions.append(h('button', { type: 'button', class: 'secondary', text: 'Download JSON', onclick: () => {
        const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
        const a = h('a', { href: url, download: `faultseeker-capture-${data.transaction_hash.slice(0, 10)}.json` });
        document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      } }));
    }
    actions.append(h('button', { type: 'button', class: 'primary', onclick: () => { location.hash = ''; }, text: 'New analysis' }));
    box.append(h('div', { class: 'page-heading' },
      h('div', null, h('p', { class: 'eyebrow', text: capture ? 'SAVED CAPTURE' : 'FAULT LOCALIZATION REPORT' }), h('h1', { text: title, tabindex: '-1' })),
      actions));

    if (capture) {
      box.append(h('div', { class: 'banner', role: 'note' }, h('span', { text: 'This is a recorded capture. No live analysis was performed and no model was called.' })));
    }
    if (data.warnings && data.warnings.length) {
      box.append(h('div', { class: 'banner', dataset: { tone: 'warn' }, role: 'note' },
        h('ul', null, data.warnings.map((w) => h('li', { text: w })))));
    }

    const stats = data.stats || {};
    const run = data.run || {};
    const facts = [
      ['Transaction', explorerLink('tx', chain, data.transaction_hash)],
      ['Network', chainLabel(chain)],
      !capture && run.model ? ['Model', (modelInfo(run.model) || { label: run.model }).label] : null,
      ['Completed', data.timestamp ? fmtDate(data.timestamp) : (run.finished_at ? fmtDate(run.finished_at) : '—')],
      !capture ? ['Duration', fmtDuration(data.duration)] : null,
      stats.functions_to_inspect != null ? ['Functions inspected', String(stats.functions_to_inspect)] : null,
    ].filter(Boolean);
    box.append(h('dl', { class: 'facts' }, facts.map(([k, v]) => h('div', { class: 'fact' }, h('dt', { text: k }), h('dd', null, v)))));

    const ranking = data.ranking || [];
    const left = h('section', { class: 'panel' },
      h('div', { class: 'section-heading' }, h('h2', { text: 'Ranked suspicious functions' }),
        h('span', { class: 'muted', text: `${ranking.length} ${ranking.length === 1 ? 'function' : 'functions'}` })));
    if (ranking.length) {
      left.append(h('ol', { class: 'finding-list' }, ranking.map((f, i) => findingNode(f, chain, { top: i === 0 && !f.unranked, rank: f.rank || i + 1 }))));
    } else {
      left.append(h('p', { class: 'empty', text: 'The analysis did not point at any functions for this transaction.' }));
    }
    const right = h('section', { class: 'panel understanding' }, h('div', { class: 'section-heading' }, h('h2', { text: 'Transaction understanding' })));
    right.append(data.understanding && data.understanding.trim() ? safeMarkdown(data.understanding) : h('p', { class: 'empty', text: 'No narrative was produced for this transaction.' }));
    box.append(h('div', { class: 'report-grid' }, left, right));

    if (data.candidates && data.candidates.length) {
      box.append(h('section', { class: 'panel candidates' },
        h('div', { class: 'section-heading' }, h('h2', { text: 'Other candidates' }), h('span', { class: 'muted', text: 'NOT RANKED' })),
        h('ol', { class: 'finding-list' }, data.candidates.map((f, i) => findingNode(f, chain, { rank: '–' })))));
    }

    if (opts.runId) {
      const pre = h('pre', { tabindex: '0', 'aria-label': 'Pipeline technical logs', text: '' });
      const details = h('details', { class: 'panel technical run-log', ontoggle: async (e) => {
        if (!e.currentTarget.open || pre.dataset.loaded) return;
        pre.dataset.loaded = '1';
        pre.textContent = 'Loading…';
        try {
          const r = await api(`/api/runs/${opts.runId}?l=0`);
          pre.textContent = r.ok ? (r.data.logs.join('\n') || 'No log output was recorded.') : 'Logs are not available.';
        } catch (_) { pre.textContent = 'Logs could not be loaded.'; delete pre.dataset.loaded; }
      } }, h('summary', null, 'Technical logs'), pre);
      box.append(details);
    }
    const heading = box.querySelector('h1');
    if (heading) heading.focus({ preventScroll: true });
  }

  /* ---------- history ---------- */
  async function showHistory() {
    showView('history');
    const list = $('history-list');
    clear(list);
    list.append(h('p', { class: 'hint', text: 'Loading recent runs…' }));
    try {
      const r = await api('/api/runs');
      if (!r.ok) throw new Error('history');
      renderHistory(r.data.runs);
    } catch (_) {
      clear(list);
      notify('Could not load recent runs.', { kind: 'error', actions: [{ label: 'Retry', onClick: showHistory }] });
    }
  }

  function renderHistory(runs) {
    const list = $('history-list');
    clear(list);
    if (!runs.length) {
      list.append(h('p', { class: 'history-empty', text: 'No analyses yet. Run one from the setup page and it will appear here.' }));
      return;
    }
    const tone = { completed: 'ok', running: 'info', failed: 'bad', cancelled: 'warn', interrupted: 'warn' };
    const now = Date.now() / 1000;
    for (const run of runs) {
      let sub;
      if (run.state === 'completed' && run.summary) {
        sub = `${run.summary.findings} ranked ${run.summary.findings === 1 ? 'function' : 'functions'}` + (run.summary.top_function ? ` · top: ${run.summary.top_function}` : '');
      } else if (run.state === 'running') sub = 'In progress';
      else sub = (run.error && run.error.message) || (run.state === 'cancelled' ? 'Cancelled before it finished' : '');
      list.append(h('button', { type: 'button', class: 'history-row', onclick: () => { location.hash = run.state === 'completed' ? `#result/${run.id}` : `#run/${run.id}`; } },
        h('span', { class: 'hash', text: run.txn_hash }),
        h('span', { class: 'meta' }, h('span', { class: 'pill', text: (chainInfo(run.chain) || { short: run.chain }).short }),
          h('span', { class: 'pill', dataset: { tone: tone[run.state] || '' }, text: (BADGE[run.state] || run.state).toUpperCase() })),
        h('span', { class: 'sub', text: [timeAgo(now - run.created_at), (modelInfo(run.model) || { label: run.model }).label, sub].filter(Boolean).join(' · ') })));
    }
  }

  /* ---------- wiring ---------- */
  function bind() {
    $('analysis-form').addEventListener('submit', submit);
    for (const id of ['transaction', 'model-key']) $(id).addEventListener('input', () => { setFieldError(id, ''); validateForm(); });
    for (const id of ['rpc-url', 'rpc-key']) $(id).addEventListener('input', () => setFieldError(id, ''));
    $('chain').addEventListener('change', () => {
      validateForm();
      const info = chainInfo($('chain').value);
      if (info && info.support === 'beta') {
        notify(`${info.label} is in beta.`, { kind: 'info', detail: 'The pipeline is wired for this network but was only benchmarked on Ethereum and BNB Smart Chain. Replaying older transactions needs an archive RPC with call tracing (see RPC connection).' });
      } else if (info && info.support === 'partial') {
        notify(`${info.label} has limited support.`, { kind: 'warn', sticky: true, detail: info.note });
      }
    });
    $('model').addEventListener('change', () => { setFieldError('model-key', ''); updateKeyRequirement(); validateForm(); });
    $('show-key').addEventListener('click', () => {
      const input = $('model-key');
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      $('show-key').textContent = show ? 'Hide' : 'Show';
      $('show-key').setAttribute('aria-pressed', String(show));
    });

    for (const chain of ['eth', 'bsc']) {
      const btn = $(`preset-btn-${chain}`);
      const wrap = btn.closest('.preset-chain');
      btn.addEventListener('click', () => { const open = btn.getAttribute('aria-expanded') !== 'true'; closePresets(chain); setPreset(chain, open); });
      wrap.addEventListener('pointerenter', (e) => { if (e.pointerType === 'mouse') { clearTimeout(state.presetTimer); closePresets(chain); setPreset(chain, true); } });
      wrap.addEventListener('pointerleave', (e) => { if (e.pointerType === 'mouse') { state.presetTimer = setTimeout(() => { if (!wrap.contains(document.activeElement)) setPreset(chain, false); }, 250); } });
    }
    document.addEventListener('click', (e) => { if (!e.target.closest('.preset-chain')) closePresets(); });
    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape') return;
      const open = ['eth', 'bsc'].find((c) => $(`preset-btn-${c}`).getAttribute('aria-expanded') === 'true');
      if (open) { setPreset(open, false); $(`preset-btn-${open}`).focus(); }
    });

    $('history-button').addEventListener('click', () => { location.hash = currentView === 'history' ? '' : '#history'; });
    $('history-close').addEventListener('click', () => { location.hash = ''; });
    $('capture-button').addEventListener('click', () => { location.hash = '#capture'; });
    $('cancel').addEventListener('click', cancelRun);
    window.addEventListener('hashchange', () => route());
  }

  async function init() {
    bind();
    await loadConfig();
    route(true);
    const cfg = state.config;
    if (cfg && cfg.active_run && currentView === 'setup') {
      notify('An analysis is currently running on this server.', { kind: 'info', sticky: true, actions: [{ label: 'Open it', onClick: () => { location.hash = `#run/${cfg.active_run}`; } }] });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
