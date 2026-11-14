// Browser-level tests: loads the real index.html + console.js in jsdom against a real server process
// (stand-in pipeline worker). Run from this folder:  npm install && npm test
// Environment: PYTHON (default python3). FaultSeeker's Python requirements must be importable.
import { JSDOM, CookieJar, VirtualConsole } from 'jsdom';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0, checks = 0;
const ok = (cond, msg) => { checks++; console.log((cond ? '  PASS ' : '  FAIL ') + msg); if (!cond) failures++; };
const section = (name) => console.log(`\n# ${name}`);
async function until(fn, ms = 20000, step = 80) {
  const t = Date.now();
  while (Date.now() - t < ms) { try { const v = fn(); if (v) return v; } catch { /* keep polling */ } await sleep(step); }
  return null;
}
const hash = (prefix, fill = '1') => '0x' + prefix + fill.repeat(64 - prefix.length);
const GOOD_KEY = 'good-key-' + 'k'.repeat(30);          // the fake providers accept keys that start with "good-"
const CODEX_KEY = 'good-codex-' + 'c'.repeat(24);
const BAD_KEY = 'bad-key-' + 'b'.repeat(24);
const ACCESS_CODE = 'ui test access code 123';

// ---------- fake OpenAI-compatible providers (OFFLINE test doubles on 127.0.0.1) ----------
function startFake() {
  const calls = []; let mode = 'ok';
  const srv = http.createServer((req, res) => {
    const key = (req.headers.authorization || '').replace('Bearer ', '');
    calls.push({ path: req.url, key });
    res.setHeader('content-type', 'application/json');
    if (mode === 'down') { res.statusCode = 503; return res.end('{}'); }
    if (req.url === '/v1/models' && key.startsWith('good-')) return res.end('{"data":[]}');
    res.statusCode = req.url === '/v1/models' ? 401 : 404;
    res.end('{"error":{}}');
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ calls, port: srv.address().port, setMode: (m) => { mode = m; }, close: () => srv.close() })));
}
const fakeOpenAI = await startFake();     // stands in for api.openai.com (via the test registry)
const fakeCodex = await startFake();      // stands in for the Codex proxy

// ---------- server ----------
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
const tmp = mkdtempSync(join(tmpdir(), 'fs-ui-'));
mkdirSync(join(tmp, 'bin'));
for (const tool of ['cast', 'getCode']) { writeFileSync(join(tmp, 'bin', tool), '#!/bin/sh\nexit 0\n'); chmodSync(join(tmp, 'bin', tool), 0o755); }
const port = await freePort();
const port2 = await freePort();
const closedPort = await freePort();      // nothing listens here: the Mercury endpoint is unreachable
const BASE = `http://127.0.0.1:${port}/`;
const BASE2 = `http://127.0.0.1:${port2}/`;
const registry = JSON.parse((await import('node:fs')).readFileSync(join(ROOT, 'config', 'models.json'), 'utf8'));
registry.providers.openai.base_url = `http://127.0.0.1:${fakeOpenAI.port}/v1`;
writeFileSync(join(tmp, 'models.json'), JSON.stringify(registry));
const baseEnv = { ...process.env, PATH: `${join(tmp, 'bin')}:${process.env.PATH}`, PYTHONPATH: ROOT,
  FAULTSEEKER_WORKER_MODULE: 'tests.fake_worker', FAULTSEEKER_ALLOW_PRIVATE_RPC: '1', FAULTSEEKER_OLLAMA_MODELS: 'llama3',
  FAKE_DELAY: '0.3', OPENAI_API_KEY: '', FAULTSEEKER_MODELS_FILE: join(tmp, 'models.json'),
  CODEX_PROXY_BASE_URL: `http://127.0.0.1:${fakeCodex.port}/v1`, CODEX_PROXY_MODEL: 'codex-exact',
  MERCURY_BASE_URL: `http://127.0.0.1:${closedPort}/v1`, MERCURY_MODEL: 'mercury-exact' };
const launch = (p, dataDir, extra = {}) => spawn(process.env.PYTHON || 'python3', ['-m', 'uvicorn', 'faultseeker.server.app:app', '--port', String(p), '--log-level', 'warning'],
  { cwd: ROOT, env: { ...baseEnv, FAULTSEEKER_DATA_DIR: join(tmp, dataDir), ...extra }, stdio: ['ignore', 'inherit', 'inherit'] });
const server = launch(port, 'data');
const server2 = launch(port2, 'data2', { FAULTSEEKER_ACCESS_CODE: ACCESS_CODE });   // the access-protected instance
const stop = () => { for (const s of [server, server2]) { try { s.kill('SIGTERM'); } catch { /* already gone */ } } fakeOpenAI.close(); fakeCodex.close(); };
process.on('exit', stop);
for (const b of [BASE, BASE2]) for (let i = 0; i < 100; i++) { try { if ((await fetch(b + 'api/health')).ok) break; } catch { /* not up yet */ } await sleep(200); }

// ---------- page helper ----------
const pages = [];
const jarFetch = (jar, base) => async (u, o = {}) => {       // a browser-like fetch: cookies and Origin on writes
  const url = new URL(u, base);
  const headers = { ...(o.headers || {}) };
  const cookie = jar.getCookieStringSync(url.href);
  if (cookie) headers.cookie = cookie;
  if (o.method && o.method !== 'GET') headers.origin = new URL(base).origin;
  const res = await fetch(url, { ...o, headers, redirect: 'manual' });
  for (const sc of res.headers.getSetCookie()) jar.setCookieSync(sc, url.href);
  return res;
};
async function openPage(hashPart = '', { fetchImpl, base = BASE, jar } = {}) {
  const errors = []; const navigations = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', (e) => { if (/navigation/.test(e.message)) navigations.push(1); else errors.push(e.message); });
  const dom = await JSDOM.fromURL(base + hashPart, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true, virtualConsole, ...(jar ? { cookieJar: jar } : {}),
    beforeParse(w) {
      w.fetch = fetchImpl ? (u, o) => fetchImpl(new URL(u, base), o) : jar ? jarFetch(jar, base) : (u, o) => fetch(new URL(u, base), o);
      w.confirm = () => true; w.scrollTo = () => {}; w.Element.prototype.scrollIntoView = () => {};   // not implemented by jsdom
      w.addEventListener('error', (e) => errors.push(e.message));
    },
  });
  const w = dom.window, d = w.document;
  const page = {
    w, d, errors, navigations, $: (id) => d.getElementById(id),
    click: (el) => el.dispatchEvent(new w.MouseEvent('click', { bubbles: true })),
    type(el, v) { el.value = v; el.dispatchEvent(new w.Event('input', { bubbles: true })); },
    select(el, v) { el.value = v; el.dispatchEvent(new w.Event('change', { bubbles: true })); },
    submit() { page.$('analysis-form').dispatchEvent(new w.Event('submit', { cancelable: true, bubbles: true })); },
    goto(h) { w.location.hash = h; },
    ready: () => until(() => page.$('chain').options.length > 0),
    loaded: () => until(() => d.readyState === 'complete'),     // deferred scripts have run (jsdom resolves fromURL earlier)
    async start(tx, { chain = 'bsc', key = true } = {}) {
      page.goto(''); await until(() => !page.$('setup').hidden);
      page.type(page.$('transaction'), tx); page.select(page.$('chain'), chain);
      page.select(page.$('model'), 'gpt-4o-mini'); page.type(page.$('model-key'), key ? GOOD_KEY : '');
      page.submit();
      return until(() => w.location.hash.startsWith('#run/') && w.location.hash.slice(5));
    },
    close() { w.close(); },
  };
  pages.push(page);
  return page;
}

try {
  // ======================================================================================
  section('first load, empty history');
  const p = await openPage();
  const { d, $, click, type, select } = p;
  ok(await p.ready(), 'config loaded');
  ok(/LOCAL · READY/.test($('environment').textContent) && $('environment').dataset.state === 'ok', 'environment badge ready: ' + $('environment').textContent);
  ok($('analyze').disabled, 'analyze disabled initially');
  click($('history-button'));
  ok(await until(() => !$('history').hidden && /No analyses yet/.test($('history-list').textContent)), 'empty history shows a helpful message');
  click($('history-close'));
  ok(await until(() => !$('setup').hidden), 'history Back returns to setup');

  // ======================================================================================
  section('networks and models');
  const opts = [...$('chain').options];
  ok(opts.length === 16, '16 networks listed');
  const byVal = Object.fromEntries(opts.map((o) => [o.value, o]));
  ok(byVal.eth.textContent === 'Ethereum' && byVal.bsc.textContent === 'BNB Smart Chain', 'Ethereum and BNB have no warning suffix');
  ok(byVal.polygon.textContent.endsWith('(beta)') && byVal.aurora.textContent.endsWith('(partial)'), 'beta and partial networks are labelled');
  ok(byVal.zksync.disabled && /not supported/.test(byVal.zksync.textContent) && byVal.zksync.title.length > 10, 'zkSync is disabled with an explanation');
  select($('chain'), 'polygon');
  ok(!$('notice').hidden && /beta/.test($('notice').textContent), 'beta network shows an info notice');
  select($('chain'), 'fantom');
  ok(/limited support/.test($('notice').textContent) && /Stage 2/.test($('notice').textContent) && $('notice').dataset.kind === 'warn', 'partial network shows a sticky warning');
  select($('chain'), 'eth');
  ok($('model').options.length === 7, 'models: 4 OpenAI + Codex proxy + Mercury + 1 Ollama');
  ok([...$('model').options].map((o) => o.value).includes('ollama:llama3'), 'Ollama model id carries its explicit provider prefix');
  ok(/Required/.test($('key-requirement').textContent) && !$('model-key').disabled && /OpenAI/.test($('key-hint').textContent), 'OpenAI model: key required, hint names the provider');
  type($('transaction'), hash('abcd'));
  ok($('analyze').disabled, 'valid hash alone is not enough without a key');
  select($('model'), 'ollama:llama3');
  ok(/Not needed/.test($('key-requirement').textContent) && $('model-key').disabled && !$('analyze').disabled, 'Ollama model: key disabled, analyze enabled');
  select($('model'), 'gpt-4o-mini');
  ok($('analyze').disabled, 'back to OpenAI: disabled again');
  type($('transaction'), '0x123');
  type($('model-key'), GOOD_KEY);
  ok($('analyze').disabled, 'short hash keeps analyze disabled');
  type($('transaction'), hash('abcd'));
  ok(!$('analyze').disabled, 'valid hash + key enables analyze');
  click($('show-key'));
  ok($('model-key').type === 'text' && $('show-key').textContent === 'Hide' && $('show-key').getAttribute('aria-pressed') === 'true', 'show key reveals');
  click($('show-key'));
  ok($('model-key').type === 'password' && $('show-key').textContent === 'Show', 'show key toggles back');

  // ======================================================================================
  section('presets');
  ok($('preset-list-eth').querySelectorAll('.preset-item').length === 101 && $('preset-list-bsc').querySelectorAll('.preset-item').length === 13, 'ETH 101 / BNB 13 presets');
  ok($('tx-presets').options.length >= 114, 'datalist has all unique presets');
  const hover = (el, type) => { const e = new p.w.Event(type, { bubbles: false }); Object.defineProperty(e, 'pointerType', { value: 'mouse' }); el.dispatchEvent(e); };
  hover($('preset-btn-eth').closest('.preset-chain'), 'pointerenter');
  ok(!$('preset-list-eth').hidden && $('preset-btn-eth').getAttribute('aria-expanded') === 'true', 'hover opens the ETH list');
  hover($('preset-btn-bsc').closest('.preset-chain'), 'pointerenter');
  ok($('preset-list-eth').hidden && !$('preset-list-bsc').hidden, 'only one list open at a time');
  d.dispatchEvent(new p.w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  ok($('preset-list-bsc').hidden, 'Escape closes the list');
  click($('preset-btn-eth')); click(d.body);
  ok($('preset-list-eth').hidden, 'clicking outside closes the list');
  click($('preset-btn-bsc'));
  const first = $('preset-list-bsc').querySelector('.preset-item');
  ok(first.querySelector('strong').textContent.length > 0 && first.querySelector('.meta'), 'preset shows name and date/loss');
  click(first);
  ok(/^0x[0-9a-f]{64}$/.test($('transaction').value) && $('chain').value === 'bsc' && $('preset-list-bsc').hidden, 'picking a preset fills hash and network');

  // ======================================================================================
  section('field-level server errors');
  d.querySelector('details.rpc').open = true;
  type($('rpc-key'), 'abc');
  p.submit();
  ok(await until(() => d.querySelector('.field-error[data-for="rpc-key"]')), 'RPC key without a URL → inline error under that field');
  ok($('rpc-key').getAttribute('aria-invalid') === 'true' && d.activeElement === $('rpc-key'), 'field is marked invalid and focused');
  type($('rpc-key'), '');
  ok(!d.querySelector('.field-error[data-for="rpc-key"]') && !$('rpc-key').hasAttribute('aria-invalid'), 'error clears when the field is edited');
  type($('rpc-url'), 'ftp://rpc.example');
  p.submit();
  ok(await until(() => d.querySelector('.field-error[data-for="rpc-url"]')), 'bad RPC scheme → inline error');
  type($('rpc-url'), '');
  d.querySelector('details.rpc').open = false;

  // ======================================================================================
  section('successful run (live progress → report → history)');
  const secret = GOOD_KEY;
  type($('model-key'), secret);
  select($('chain'), 'bsc');
  type($('transaction'), hash('abcd'));
  p.submit();
  ok(await until(() => p.w.location.hash.startsWith('#run/')), 'navigated to run view');
  const okId = p.w.location.hash.slice(5);
  ok(await until(() => !$('running').hidden && $('stepper').children.length === 6), 'stepper shows 6 stages');
  ok(await until(() => $('stepper').querySelector('[data-status="active"]')), 'a stage becomes active from real events');
  ok(await until(() => $('active-task').textContent !== 'Connecting to the pipeline'), 'current task text updates: ' + $('active-task').textContent);
  ok(await until(() => $('activity').children.length > 1), 'activity feed fills');
  ok(await until(() => /^[1-9]\d* lines?$/.test($('log-count').textContent)), 'technical logs stream: ' + $('log-count').textContent);
  ok(await until(() => $('elapsed').textContent !== '00:00'), 'elapsed timer ticks');
  ok(await until(() => $('running').dataset.state === 'running' && /IN PROGRESS/.test(d.querySelector('.running-badge').textContent)), 'badge says in progress');
  const details = [...$('run-details').querySelectorAll('dd')].map((x) => x.textContent).join('|');
  ok(/BNB Smart Chain/.test(details) && /Supplied for this run/.test(details) && /Server connection/.test(details), 'run details: ' + details);
  ok(await until(() => p.w.location.hash.startsWith('#result/'), 40000), 'auto-navigates to the report on completion');
  ok(await until(() => d.querySelectorAll('#results .finding').length === 2), 'two ranked functions');
  ok(d.querySelector('#results .finding[data-top="true"] h3').textContent.startsWith('mint') && /TOP SUSPECT/.test($('results').textContent), 'top suspect marked');
  ok(d.querySelector('#results .finding .evidence[open]'), 'top finding evidence expanded');
  ok(/replaying a signature/.test(d.querySelector('.understanding p').textContent), 'transaction understanding shown');
  ok(!!d.querySelector('#results a[download][href*="download=raw"]'), 'download JSON link');
  const link = d.querySelector('#results .facts a');
  ok(link && link.href.startsWith('https://bscscan.com/tx/') && link.rel.includes('noopener') && link.target === '_blank', 'explorer link opens safely: ' + (link && link.href));
  click(d.querySelector('#results .addr button'));
  ok(await until(() => /Copied|Ctrl\+C/.test(d.querySelector('#results .addr button').textContent)), 'copy button gives feedback');
  ok(!d.body.textContent.includes(secret) && !$('logs').textContent.includes(secret), 'API key text appears nowhere in the page content or logs');
  ok(![...d.querySelectorAll('a')].some((a) => a.href.startsWith('javascript:')), 'no javascript: links');
  d.querySelector('#results details.technical').open = true;
  ok(await until(() => /Pipeline|Stage 1|Analyzing/.test(d.querySelector('#results details.technical pre').textContent)), 'report shows the run log on demand');
  click(d.querySelector('#results .page-heading .primary'));
  ok(await until(() => !$('setup').hidden), '"New analysis" returns to setup');
  click($('history-button'));
  ok(await until(() => $('history-list').querySelector('.history-row')), 'history lists the run');
  const row = $('history-list').querySelector('.history-row').textContent;
  ok(/COMPLETE/.test(row) && /mint/.test(row) && /BNB/.test(row) && /GPT-4o mini/.test(row), 'history row: state, chain, model, top function');
  click($('history-list').querySelector('.history-row'));
  ok(await until(() => p.w.location.hash === `#result/${okId}` && d.querySelectorAll('#results .finding').length === 2), 'history row opens the report');

  // ======================================================================================
  section('failures are explained, never shown as success');
  const failCases = [
    ['fa11', /Transaction replay failed/, /archive/i, 'FAILED'],
    ['e8e8', /Explorer page did not report/, /explorer/i, 'FAILED'],
    ['dead', /rejected the API key/, /belongs to the selected provider/, 'FAILED'],
    ['9a07', /no remaining quota/, /credit/, 'FAILED'],
    ['1c1c', /Stage 2 \(Function Analysis\) incomplete.*bar@0x.*iteration limit/, /provider key, quota and availability/, 'FAILED'],
    ['0bad', /stopped unexpectedly/, /technical logs/, 'FAILED'],
  ];
  for (const [prefix, msg, hintRe, badge] of failCases) {
    const id = await p.start(hash(prefix, '0'));
    ok(!!id, `[${prefix}] run started`);
    ok(await until(() => $('running').dataset.state === 'failed', 30000), `[${prefix}] state becomes failed`);
    const detail = d.querySelector('.error-detail');
    ok(detail && msg.test(detail.textContent) && hintRe.test(detail.textContent), `[${prefix}] message + hint: ` + (detail && detail.textContent.slice(0, 80)));
    ok(d.querySelector('.running-badge').textContent === badge && $('cancel').hidden, `[${prefix}] badge ${badge}, cancel hidden`);
    ok(!$('running').hidden && $('results').hidden, `[${prefix}] stays on the run view and shows no report`);
  }
  ok(!!d.querySelector('.error-actions .primary'), 'Back to setup action present');
  click(d.querySelector('.error-actions .secondary'));
  ok(d.querySelector('details.technical').open, '"View technical logs" opens the log panel');
  click(d.querySelector('.error-actions .primary'));
  ok(await until(() => !$('setup').hidden && $('running').hidden), 'Back to setup works');
  ok($('transaction').value === hash('0bad', '0') && $('model-key').value.length > 10, 'form values are kept so the user can retry');
  p.goto('#history');
  ok(await until(() => [...d.querySelectorAll('.history-row')].some((r) => /FAILED/.test(r.textContent) && /Transaction replay failed/.test(r.textContent))), 'history shows failed runs with their reason');
  click([...d.querySelectorAll('.history-row')].find((r) => /FAILED/.test(r.textContent)));
  ok(await until(() => p.w.location.hash.startsWith('#run/') && $('running').dataset.state === 'failed'), 'opening a failed run shows its failure, not a report');

  // ======================================================================================
  section('unusable and empty model output');
  const badId = await p.start(hash('bad0', '0'));
  ok(await until(() => p.w.location.hash === `#result/${badId}` && d.querySelectorAll('#results .finding').length > 0, 40000), 'run with a failed model call completes');
  ok(/UNRANKED/.test($('results').textContent) && d.querySelector('#results .banner[data-tone="warn"]'), 'unranked findings and warning banner shown');
  ok(!/an error occurred/i.test($('results').textContent), 'model error text is never shown as a finding');
  ok(d.querySelector('#results .finding[data-top="true"]') === null, 'no function is crowned "top suspect" when ranking failed');
  const emptyId = await p.start(hash('0000', '2'));
  ok(await until(() => p.w.location.hash === `#result/${emptyId}` && /did not point at any functions/.test($('results').textContent), 40000), 'empty result is stated plainly');
  ok(/No potentially vulnerable functions/.test($('results').textContent), 'warning explains the empty result');

  // ======================================================================================
  section('saved capture');
  p.goto('#capture');
  ok(await until(() => /recorded capture/.test($('results').textContent)), 'capture banner: no live analysis');
  ok($('results').querySelector('.eyebrow').textContent === 'SAVED CAPTURE' && $('results').querySelector('.finding h3').textContent.startsWith('mint'), 'capture shows the annotated function');
  ok(!!$('results').querySelector('.page-heading button.secondary') && !$('results').querySelector('details.technical'), 'capture has a download button and no run log');

  // ======================================================================================
  section('routing, reload and bookmarks');
  const q = await openPage(`#result/${okId}`);
  ok(await until(() => q.d.querySelectorAll('#results .finding').length === 2), 'opening #result/<id> directly renders the report');
  q.close();
  const r = await openPage(`#run/${okId}`);
  ok(await until(() => r.w.location.hash === `#result/${okId}`), 'opening a finished #run/<id> redirects to its report');
  r.close();
  const s = await openPage('#result/0123456789abcdef');
  ok(await until(() => !s.$('notice').hidden && s.$('notice').dataset.kind === 'error' && !s.$('setup').hidden), 'unknown run → error notice and back to setup');
  s.close();
  const t = await openPage('#history');
  ok(await until(() => !t.$('history').hidden && t.d.querySelectorAll('.history-row').length >= 8), 'opening #history directly lists runs');
  t.close();

  // ======================================================================================
  section('busy server and cancellation');
  const runningId = await p.start(hash('4a49', '0'));    // "hang" scenario
  p.goto('');
  await until(() => !$('setup').hidden);
  type($('transaction'), hash('abcd'));
  p.submit();
  ok(await until(() => !$('notice').hidden && /already running/.test($('notice').textContent)), 'second submit gets a busy notice');
  const openBtn = [...$('notice').querySelectorAll('button')].find((b) => b.textContent === 'Open running analysis');
  ok(!!openBtn, 'busy notice offers to open the running analysis');
  click(openBtn);
  ok(await until(() => p.w.location.hash === `#run/${runningId}` && !$('cancel').hidden), 'opens the running analysis');
  click($('cancel'));
  ok(await until(() => $('running').dataset.state === 'cancelled', 20000), 'cancel → cancelled state');
  ok($('cancel').hidden && /CANCELLED/.test(d.querySelector('.running-badge').textContent) && !!d.querySelector('.error-actions'), 'cancelled UI: badge, no cancel button, way back');
  ok(!d.querySelector('.error-detail'), 'cancellation is not presented as an error');

  // ======================================================================================
  section('providers, key rules and key validation (against local fake providers)');
  p.goto(''); await until(() => !$('setup').hidden);
  select($('model'), 'codex-proxy');
  ok(/Required/.test($('key-requirement').textContent) && /Codex proxy/.test($('key-hint').textContent), 'Codex proxy: key hint names Codex proxy');
  select($('model'), 'mercury');
  ok(/Inception Mercury/.test($('key-hint').textContent), 'Mercury: key hint names Inception Mercury');
  const countRuns = async () => (await (await fetch(BASE + 'api/runs')).json()).runs.length;
  const runsBefore = await countRuns();
  select($('chain'), 'bsc'); type($('transaction'), hash('cafe'));

  select($('model'), 'codex-proxy'); type($('model-key'), BAD_KEY); p.submit();
  ok(await until(() => d.querySelector('.field-error[data-for="model-key"]')), 'invalid key → error under the key field');
  ok(/Codex proxy/.test(d.querySelector('.field-error[data-for="model-key"]').textContent) && /rejected/.test(d.querySelector('.field-error[data-for="model-key"]').textContent), 'error names the provider that rejected it');
  ok(await countRuns() === runsBefore && !p.w.location.hash.startsWith('#run/'), 'an invalid key starts nothing');

  select($('model'), 'mercury'); type($('model-key'), GOOD_KEY); p.submit();
  ok(await until(() => !$('notice').hidden && /Could not verify the API key/.test($('notice').textContent)), 'unreachable provider → "could not verify" notice');
  ok($('notice').dataset.kind === 'warn' && !p.w.location.hash.startsWith('#run/') && await countRuns() === runsBefore, 'an unreachable provider is NOT treated as a valid key');

  fakeOpenAI.setMode('down');
  select($('model'), 'gpt-4o-mini'); p.submit();
  ok(await until(() => /Could not verify the API key/.test($('notice').textContent) && !p.w.location.hash.startsWith('#run/')), 'provider outage (503) blocks the run too');
  ok(await countRuns() === runsBefore, 'still nothing started');
  fakeOpenAI.setMode('ok');

  select($('model'), 'codex-proxy'); type($('model-key'), CODEX_KEY); p.submit();
  ok(await until(() => p.w.location.hash.startsWith('#run/')), 'valid key at the selected provider → run starts');
  ok(await until(() => [...$('run-details').querySelectorAll('dd')].some((x) => x.textContent === 'Codex proxy')), 'run details show the provider');
  ok(await until(() => p.w.location.hash.startsWith('#result/'), 40000), 'run completes');
  const keysAt = (f) => new Set(f.calls.map((c) => c.key));
  ok([...keysAt(fakeOpenAI)].every((k) => k === GOOD_KEY), 'OpenAI endpoint only ever received the OpenAI-flow key: ' + [...keysAt(fakeOpenAI)].join(','));
  ok([...keysAt(fakeCodex)].every((k) => k === BAD_KEY || k === CODEX_KEY) && keysAt(fakeCodex).has(CODEX_KEY), 'Codex endpoint only received Codex-flow keys');
  ok(!fakeOpenAI.calls.some((c) => c.key === CODEX_KEY || c.key === BAD_KEY) && !fakeCodex.calls.some((c) => c.key === GOOD_KEY), 'no key was ever sent to the other provider');
  ok(!d.body.textContent.includes(CODEX_KEY) && !$('logs').textContent.includes(CODEX_KEY), 'the key text is nowhere in the page');
  p.goto('');

  // ======================================================================================
  section('access protection (second server, access code, cookie jar)');
  const jar = new CookieJar();
  const gate = await openPage('', { base: BASE2, jar });
  await gate.loaded();
  ok(gate.w.location.pathname === '/login' && !!gate.$('login-form') && !gate.$('setup'), 'an unauthenticated visit lands on the sign-in page, not the console');
  ok(!gate.d.documentElement.outerHTML.includes('Analyze transaction'), 'no console content is served before sign-in');
  ok(gate.d.querySelectorAll('script:not([src])').length === 0, 'sign-in page has no inline scripts');
  gate.type(gate.$('code'), 'not the code');
  gate.$('login-form').dispatchEvent(new gate.w.Event('submit', { cancelable: true, bubbles: true }));
  ok(await until(() => !gate.$('login-error').hidden && /Incorrect access code/.test(gate.$('login-error').textContent)), 'wrong code → clear error');
  ok(gate.$('code').value === '' && gate.$('code').getAttribute('aria-invalid') === 'true' && jar.getCookiesSync(BASE2).length === 0, 'field cleared, no cookie issued');
  gate.type(gate.$('code'), ACCESS_CODE);
  gate.$('login-form').dispatchEvent(new gate.w.Event('submit', { cancelable: true, bubbles: true }));
  ok(await until(() => jar.getCookiesSync(BASE2).some((c) => c.key === 'fs_session')), 'correct code → session cookie');
  const cookie = jar.getCookiesSync(BASE2).find((c) => c.key === 'fs_session');
  ok(cookie.httpOnly && String(cookie.sameSite).toLowerCase() === 'strict', 'cookie is HttpOnly and SameSite=Strict');
  ok(gate.navigations.length >= 1, 'page navigates to the console after signing in');
  gate.close();

  const inside = await openPage('', { base: BASE2, jar });
  ok(await inside.ready() && !!inside.$('signout'), 'signed in: console loads and shows Sign out');
  ok(inside.$('analyze').disabled && inside.$('model').options.length === 7, 'console works under protection');
  const keep = await inside.start(hash('beef'), { chain: 'bsc' });
  ok(!!keep && await until(() => inside.w.location.hash.startsWith('#result/'), 40000), 'a full run works through the protected API (polling, results)');
  inside.click(inside.$('signout'));
  ok(await until(() => !jar.getCookiesSync(BASE2).some((c) => c.key === 'fs_session' && c.expiryTime && c.expiryTime() > Date.now()) || jar.getCookiesSync(BASE2).length === 0), 'Sign out clears the cookie');
  ok(await until(() => inside.navigations.length >= 1), 'and returns to the sign-in page');
  ok((await fetch(BASE2 + 'api/runs', { headers: { cookie: `fs_session=${cookie.value}` } })).status === 401, 'the old session token no longer works (revoked server-side)');
  inside.close();

  // a session that disappears while the console is open sends the user to sign in
  const jar2 = new CookieJar();
  const lg = await openPage('', { base: BASE2, jar: jar2 });
  await lg.loaded();
  lg.type(lg.$('code'), ACCESS_CODE);
  lg.$('login-form').dispatchEvent(new lg.w.Event('submit', { cancelable: true, bubbles: true }));
  await until(() => jar2.getCookiesSync(BASE2).length > 0); lg.close();
  const live = await openPage('', { base: BASE2, jar: jar2 });
  await live.ready();
  await fetch(BASE2 + 'auth/logout', { method: 'POST', headers: { cookie: jar2.getCookieStringSync(BASE2) } });   // revoke behind its back
  const navBefore = live.navigations.length;
  live.click(live.$('history-button'));
  ok(await until(() => live.navigations.length > navBefore), 'an expired session sends the user back to sign in');
  ok(live.$('notice').hidden, 'without a confusing error message');
  live.close();

  // rate limiting is shown to the user
  const jar3 = new CookieJar();
  const brute = await openPage('', { base: BASE2, jar: jar3 });
  await brute.loaded();
  for (let i = 0; i < 6; i++) {
    brute.type(brute.$('code'), 'wrong' + i);
    brute.$('login-form').dispatchEvent(new brute.w.Event('submit', { cancelable: true, bubbles: true }));
    await until(() => !brute.$('login-error').hidden && !brute.$('login-submit').disabled); await sleep(60);
  }
  ok(/Too many failed attempts/.test(brute.$('login-error').textContent), 'repeated wrong codes → rate-limit message: ' + brute.$('login-error').textContent);
  brute.type(brute.$('code'), ACCESS_CODE);
  brute.$('login-form').dispatchEvent(new brute.w.Event('submit', { cancelable: true, bubbles: true }));
  await sleep(500);
  ok(jar3.getCookiesSync(BASE2).length === 0, 'even the right code is refused while locked out');
  brute.close();

  // ======================================================================================
  section('server unreachable');
  const off = await openPage('', { fetchImpl: () => Promise.reject(new TypeError('network down')) });
  ok(await until(() => off.$('environment').textContent === 'OFFLINE'), 'badge shows OFFLINE');
  ok(await until(() => !off.$('notice').hidden && off.$('notice').dataset.kind === 'error' && /Retry/.test(off.$('notice').textContent)), 'error notice with Retry');
  ok(off.$('analyze').disabled, 'analyze stays disabled offline');
  off.close();

  // ======================================================================================
  section('untrusted text is never interpreted as HTML');
  const evil = '<img src=x onerror="window.__pwned=1">';
  const crafted = {
    kind: 'capture', transaction_hash: hash('abcd'), chain: 'eth', timestamp: evil, duration: null,
    understanding: evil + '<script>window.__pwned=2</script>', warnings: [evil],
    ranking: [{ rank: 1, function: evil, address: '0x' + 'a'.repeat(40), evidence: [evil] }],
    candidates: [{ function: '<b>x</b>', address: '', evidence: [] }], stats: {},
  };
  const x = await openPage('#capture', {
    fetchImpl: (url, o) => (url.pathname === '/api/capture' ? Promise.resolve(new Response(JSON.stringify(crafted), { status: 200, headers: { 'content-type': 'application/json' } })) : fetch(url, o)),
  });
  ok(await until(() => x.$('results').querySelector('.finding')), 'crafted capture rendered');
  ok(x.$('results').querySelectorAll('img, script, b').length === 0 && !x.w.__pwned, 'no injected elements or script execution');
  ok(x.$('results').textContent.includes(evil), 'markup shown as literal text');
  x.close();
  // ======================================================================================
  section('safe markdown renders the supported subset as DOM elements');
  const markdownCapture = {
    kind: 'capture',
    transaction_hash: hash('abcd'),
    chain: 'eth',
    timestamp: '',
    duration: null,
    understanding: [
      'A **bold** word and an *italic* word with `inline code`.',
      '',
      '- First list item',
      '* Second list item',
    ].join('\n'),
    warnings: [],
    ranking: [{
      rank: 1,
      function: 'exampleFunction',
      address: '0x' + 'a'.repeat(40),
      evidence: ['Evidence with **bold**, *italic*, and `code`.'],
    }],
    candidates: [],
    stats: {},
  };
  const markdownPage = await openPage('#capture', {
    fetchImpl: (url, o) => (
      url.pathname === '/api/capture'
        ? Promise.resolve(new Response(JSON.stringify(markdownCapture), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }))
        : fetch(url, o)
    ),
  });

  const understanding = await until(() => markdownPage.$('results').querySelector('.understanding .safe-markdown'));
  ok(!!understanding, 'capture understanding rendered');
  ok(understanding?.querySelector('strong')?.textContent === 'bold', 'bold syntax renders as strong');
  ok(understanding?.querySelector('em')?.textContent === 'italic', 'italic syntax renders as em');
  ok(understanding?.querySelector('code')?.textContent === 'inline code', 'inline code syntax renders as code');
  ok(
    understanding?.querySelectorAll('ul > li').length === 2 &&
      understanding.querySelector('ul > li')?.textContent === 'First list item',
    'simple unordered-list lines render as list items',
  );

  const evidence = markdownPage.$('results').querySelector('.finding .evidence ul');
  ok(!!evidence?.querySelector('strong'), 'evidence bold syntax renders as strong');
  ok(!!evidence?.querySelector('em'), 'evidence italic syntax renders as em');
  ok(!!evidence?.querySelector('code'), 'evidence inline code syntax renders as code');
  markdownPage.close();

  // ======================================================================================
  section('HTML and javascript URLs remain visible literal text');
  const hostileText = '<img src=x onerror="window.__pwned=1"> <script>window.__pwned=2</script> [click](javascript:window.__pwned=3)';
  const hostileCapture = {
    kind: 'capture',
    transaction_hash: hash('abcd'),
    chain: 'eth',
    timestamp: '',
    duration: null,
    understanding: hostileText,
    warnings: [],
    ranking: [{
      rank: 1,
      function: 'exampleFunction',
      address: '',
      evidence: [hostileText],
    }],
    candidates: [],
    stats: {},
  };
  const hostilePage = await openPage('#capture', {
    fetchImpl: (url, o) => (
      url.pathname === '/api/capture'
        ? Promise.resolve(new Response(JSON.stringify(hostileCapture), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }))
        : fetch(url, o)
    ),
  });

  const hostileUnderstanding = await until(() => hostilePage.$('results').querySelector('.understanding .safe-markdown'));
  ok(!!hostileUnderstanding, 'hostile capture understanding rendered');
  ok(hostileUnderstanding?.textContent.includes('<img src=x'), 'HTML image tag remains visible text');
  ok(hostileUnderstanding?.textContent.includes('<script>'), 'HTML script tag remains visible text');
  ok(hostileUnderstanding?.textContent.includes('javascript:'), 'javascript URL remains visible text');
  ok(
    hostileUnderstanding?.querySelectorAll('img, script, a').length === 0,
    'hostile understanding creates no image, script, or link elements',
  );
  ok(
    hostileUnderstanding?.innerHTML.includes('<script') === false &&
      hostileUnderstanding?.innerHTML.includes('<img') === false,
    'understanding DOM contains no injected script or image markup',
  );
  ok(!hostilePage.w.__pwned, 'hostile text executes no script');
  const hostileEvidence = hostilePage.$('results').querySelector('.finding .evidence');
  ok(hostileEvidence?.textContent.includes('<img src=x'), 'evidence HTML remains visible text');
  ok(hostileEvidence?.textContent.includes('javascript:'), 'evidence javascript URL remains visible text');
  ok(
    hostileEvidence?.querySelectorAll('img, script, a').length === 0,
    'evidence creates no image, script, or link elements',
  );
  hostilePage.close();

  // ======================================================================================
  section('safe markdown preserves multiple narrative paragraphs');
  const paragraphsCapture = {
    kind: 'capture',
    transaction_hash: hash('abcd'),
    chain: 'eth',
    timestamp: '',
    duration: null,
    understanding: 'First paragraph.\n\nSecond paragraph.\n\nThird paragraph.',
    warnings: [],
    ranking: [],
    candidates: [],
    stats: {},
  };
  const paragraphsPage = await openPage('#capture', {
    fetchImpl: (url, o) => (
      url.pathname === '/api/capture'
        ? Promise.resolve(new Response(JSON.stringify(paragraphsCapture), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }))
        : fetch(url, o)
    ),
  });

  const paragraphs = await until(() => {
    const container = paragraphsPage.$('results').querySelector('.understanding .safe-markdown');
    return container?.querySelectorAll(':scope > p').length === 3 ? container : null;
  });
  ok(!!paragraphs, 'three blank-line-separated paragraphs render as three paragraphs');
  ok(
    Array.from(paragraphs?.querySelectorAll(':scope > p') || []).map((p) => p.textContent).join('|') ===
      'First paragraph.|Second paragraph.|Third paragraph.',
    'paragraph text and order are preserved',
  );
  paragraphsPage.close();

  // ======================================================================================
  section('empty and whitespace-only understanding uses the empty-state fallback');
  for (const emptyUnderstanding of ['', '   \n \t\n']) {
    const emptyCapture = {
      kind: 'capture',
      transaction_hash: hash('abcd'),
      chain: 'eth',
      timestamp: '',
      duration: null,
      understanding: emptyUnderstanding,
      warnings: [],
      ranking: [],
      candidates: [],
      stats: {},
    };
    const emptyPage = await openPage('#capture', {
      fetchImpl: (url, o) => (
        url.pathname === '/api/capture'
          ? Promise.resolve(new Response(JSON.stringify(emptyCapture), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }))
          : fetch(url, o)
      ),
    });

    const emptyPanel = await until(() => emptyPage.$('results').querySelector('.understanding'));
    ok(!!emptyPanel, 'empty understanding panel rendered');
    ok(
      emptyPanel?.querySelector('.safe-markdown') === null,
      'empty understanding does not create a safe-markdown container',
    );
    ok(
      emptyPanel?.querySelector('.empty')?.textContent === 'No narrative was produced for this transaction.',
      'empty understanding displays the existing empty-state fallback',
    );
    emptyPage.close();
  }

} catch (err) {
  console.error('\nTEST HARNESS ERROR:', err);
  failures++;
} finally {
  const allErrors = pages.flatMap((pg) => pg.errors);
  section('hygiene');
  ok(allErrors.length === 0, 'no uncaught JS errors in any page ' + JSON.stringify(allErrors));
  pages.forEach((pg) => { try { pg.close(); } catch { /* closed */ } });
  stop();
  console.log(failures ? `\n${failures} of ${checks} CHECKS FAILED` : `\nALL ${checks} UI CHECKS PASSED`);
  process.exit(failures ? 1 : 0);
}
