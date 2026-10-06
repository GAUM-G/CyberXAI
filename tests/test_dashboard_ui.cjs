const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const { runInNewContext } = require('node:vm');

const templates = join(__dirname, '..', 'dashboard', 'templates');

test('show/hide buttons toggle passwords without submitting their form', () => {
  const template = readFileSync(join(templates, 'auth_base.html'), 'utf8');
  const script = template.match(/<script>([\s\S]*?)<\/script>/)[1];
  const inputs = { password: { type: 'password' }, confirm_password: { type: 'password' } };
  const buttons = Object.keys(inputs).map(id => ({
    dataset: { togglePassword: id },
    attributes: {},
    addEventListener(event, callback) { this.click = callback; },
    setAttribute(name, value) { this.attributes[name] = value; },
  }));
  runInNewContext(script, { document: {
    querySelectorAll: () => buttons,
    getElementById: id => inputs[id],
  } });
  for (const button of buttons) {
    button.click();
    assert.equal(inputs[button.dataset.togglePassword].type, 'text');
    assert.equal(button.attributes['aria-label'], 'Hide password');
    assert.equal(button.attributes['aria-pressed'], 'true');
    button.click();
    assert.equal(inputs[button.dataset.togglePassword].type, 'password');
    assert.equal(button.attributes['aria-label'], 'Show password');
    assert.equal(button.attributes['aria-pressed'], 'false');
  }
  for (const name of ['login.html', 'set_password.html']) {
    const html = readFileSync(join(templates, name), 'utf8');
    const fields = [...html.matchAll(/<input id="([^"]+)"[^>]*type="password"/g)];
    for (const [, id] of fields) {
      assert.ok(html.includes(`data-toggle-password="${id}"`));
    }
    const toggles = [...html.matchAll(/<button[^>]*data-toggle-password[^>]*>/g)];
    assert.ok(toggles.length);
    for (const [tag] of toggles) assert.ok(tag.includes('type="button"'));
  }
});

function ipsContext(overrides = {}) {
  const html = readFileSync(join(templates, 'index.html'), 'utf8');
  const script = html.slice(html.indexOf('function ipsActionLabel('), html.indexOf('function clampPercent('));
  assert.ok(script.includes('async function loadIPSWorkspace'));
  const elements = new Map();
  const buttons = [{ disabled: false, dataset: {} }, { disabled: true, dataset: {} }];
  const context = {
    ipsActionPending: false, ipsLoadVersion: 0, ipsRecommendations: [], ipsActions: [],
    document: { getElementById(id) {
      if (!elements.has(id)) elements.set(id, { textContent: '', innerHTML: '', className: '' });
      return elements.get(id);
    }, querySelectorAll: () => buttons },
    feather: { replace() {} }, window: { confirm: () => true },
    esc: String, fmtTs: String, svcBadge: String, attackLabel: String, threatBadge: String,
    ...overrides,
  };
  runInNewContext(script, context);
  return { context, elements, buttons };
}

test('IPS controls expose termination only for FTP and suppress unsafe event actions', () => {
  const { context } = ipsContext();
  const rec = { prediction: 'attack', status: 'pending', session_id: 'session-1', service: 'ftp' };
  assert.match(context.ipsRecommendationButtons(rec, 0), /onclick="runIPSRecommendationAction\('terminate_session'/);
  for (const service of ['http', 'ssh']) {
    const controls = context.ipsRecommendationButtons({ ...rec, service }, 0);
    assert.match(controls, /Session termination unavailable/);
    assert.doesNotMatch(controls, /onclick="runIPSRecommendationAction\('terminate_session'/);
  }
  for (const override of [{ status: 'suppressed' }, { status: 'dismissed' }, { prediction: 'normal' }, { feedback_verdict: 'false_positive' }]) {
    assert.equal(context.ipsRecommendationButtons({ ...rec, ...override }, 0), '<span class="td-muted">Response suppressed</span>');
  }
  assert.doesNotMatch(context.ipsRecommendationButtons({ ...rec, status: 'executed' }, 0), /onclick="runIPSRecommendationAction\('dismiss'/);
});

test('invalid safety responses clear stale IPS controls', async () => {
  const { context, elements } = ipsContext({ analystRequest: async () => ({ mode: 'active', automatic_host_blocking: true, host_firewall_changed: true }) });
  context.ipsRecommendations = [{ recommendation_id: 1 }];
  await context.loadIPSWorkspace();
  assert.equal(context.ipsRecommendations.length, 0);
  assert.equal(elements.get('ips-status-message').className, 'feedback-message error');
  assert.match(elements.get('ips-recommendations-wrap').textContent, /unavailable/);
});

test('double clicks record only one IPS action and restore controls on failure', async () => {
  let resolveRequest;
  let posts = 0;
  const pending = new Promise(resolve => { resolveRequest = resolve; });
  const { context, buttons } = ipsContext({ analystRequest: async (_path, options) => {
    if (options?.method === 'POST') { posts += 1; await pending; throw new Error('Test service unavailable'); }
    throw new Error('Unexpected read');
  } });
  context.ipsRecommendations = [{ recommendation_id: 1, source_ip: '127.0.0.1' }];
  const first = context.runIPSRecommendationAction('rate_limit', 0);
  assert.equal(buttons[0].disabled, true);
  await context.runIPSRecommendationAction('rate_limit', 0);
  assert.equal(posts, 1);
  resolveRequest();
  await first;
  assert.equal(context.ipsActionPending, false);
  assert.equal(buttons[0].disabled, false);
  assert.equal(buttons[1].disabled, true);
});

test('an older IPS refresh cannot overwrite a newer refresh', async () => {
  let resolveOldSafety;
  let safetyCalls = 0;
  const safety = { mode: 'simulation', automatic_host_blocking: false, host_firewall_changed: false };
  const oldSafety = new Promise(resolve => { resolveOldSafety = resolve; });
  const { context } = ipsContext({ analystRequest: async route => {
    if (route === '/api/ips/safety') return ++safetyCalls === 1 ? oldSafety : safety;
    if (route === '/api/ips/status') return safety;
    if (route.startsWith('/api/ips/recommendations')) return { recommendations: [{ recommendation_id: 2, prediction: 'normal' }] };
    return { actions: [] };
  } });
  const first = context.loadIPSWorkspace();
  await context.loadIPSWorkspace();
  resolveOldSafety(safety);
  await first;
  assert.equal(context.ipsRecommendations[0].recommendation_id, 2);
});
