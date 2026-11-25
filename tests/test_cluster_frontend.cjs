// Multi-node transport: which requests carry the node selector and which never do.
// Compiles the real lib/api-config.ts (no bundler, no network).
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), vm = require('node:vm')
const root = path.resolve(__dirname, '..'), ts = require(root + '/AppImage/node_modules/typescript')
const code = ts.transpileModule(fs.readFileSync(root + '/AppImage/lib/api-config.ts', 'utf8'),
  { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText

function load(selected) {
  const store = new Map(selected ? [['proxmenux-selected-node', selected]] : [])
  const sent = []
  const events = []
  const window = {
    localStorage: { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: k => store.delete(k) },
    dispatchEvent: e => events.push(e.type), location: { protocol: 'https:', hostname: 'h', port: '' },
  }
  const context = {
    exports: {}, process: { env: {} }, console: { error() {} }, window, localStorage: window.localStorage, CustomEvent: class { constructor(t, i) { this.type = t; this.detail = i && i.detail } },
    fetch: async (url, opts) => { sent.push({ url, headers: opts.headers }); return new Response('{"ok":true}', { headers: { 'Content-Type': 'application/json' } }) },
  }
  vm.runInNewContext(code, context)
  return { api: context.exports, sent, events, store }
}

async function main() {
  // no selection (single node install): nothing is added
  let t = load(null)
  await t.api.fetchApi('/api/system')
  assert.equal(t.sent[0].headers['X-ProxMenux-Node'], undefined)

  // selected node is sent on node-scoped endpoints
  t = load('pve-2')
  await t.api.fetchApi('/api/system')
  await t.api.fetchApi('/api/vms')
  await t.api.fetchApi('/api/node/metrics?timeframe=day')
  assert.deepEqual(t.sent.map(s => s.headers['X-ProxMenux-Node']), ['pve-2', 'pve-2', 'pve-2'])

  // instance-level endpoints are never node-routed (login, settings, cluster list)
  for (const ep of ['/api/auth/status', '/api/cluster/nodes', '/api/notifications/settings', '/api/platform',
                    '/api/health/thresholds', '/api/apps/custom-links', '/api/proxmenux/update-status']) {
    t.sent.length = 0
    await t.api.fetchApi(ep)
    assert.equal(t.sent[0].headers['X-ProxMenux-Node'], undefined, ep)
  }
  // ...but node STATUS endpoints are
  t.sent.length = 0
  await t.api.fetchApi('/api/health/full')
  assert.equal(t.sent[0].headers['X-ProxMenux-Node'], 'pve-2')

  // guest requests go to the node that hosts the guest, whatever is selected
  t.api.registerGuestNodes([{ vmid: 201, node: 'pve-1' }, { vmid: 100, node: 'pve' }])
  t.sent.length = 0
  await t.api.fetchApi('/api/vms/201')
  await t.api.fetchApi('/api/vms/201/control', { method: 'POST', body: '{}' })
  await t.api.fetchApi('/api/lxc/100/mount-points')
  await t.api.fetchApi('/api/vms/999')
  assert.deepEqual(t.sent.map(s => s.headers['X-ProxMenux-Node']), ['pve-1', 'pve-1', 'pve', 'pve-2'])

  // an explicit header from the caller wins
  t.sent.length = 0
  await t.api.fetchApi('/api/vms', { headers: { 'X-ProxMenux-Node': 'pve' } })
  assert.equal(t.sent[0].headers['X-ProxMenux-Node'], 'pve')

  // invalid / tampered stored values are ignored, never sent
  for (const bad of ['../etc', 'a b', 'x'.repeat(70), 'pve;rm']) {
    t = load(bad)
    await t.api.fetchApi('/api/system')
    assert.equal(t.sent[0].headers['X-ProxMenux-Node'], undefined, bad)
  }
  assert.equal(load('pve-1').api.getSelectedNode(), 'pve-1')

  // switching = storage + event only (no token handling, no reload)
  t = load('pve')
  t.api.storeSelectedNode('pve-3')
  assert.equal(t.store.get('proxmenux-selected-node'), 'pve-3')
  assert.deepEqual(t.events, ['proxmenux-node-changed'])
  await t.api.fetchApi('/api/system')
  assert.equal(t.sent.at(-1).headers['X-ProxMenux-Node'], 'pve-3')
  console.log('PASS cluster transport: node header on node-scoped endpoints only, guest routing, tamper-proof selection')
}
main().catch(e => { console.error(e); process.exitCode = 1 })
