// Exercise the real offline report with conflicting declarations under one name.
// PALMA_TEST_PYTHON=python3 NODE_PATH=/path/to/jsdom/node_modules node tests/report-grouped-inventory.cjs
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '..');
const rendered = spawnSync(process.env.PALMA_TEST_PYTHON || 'python3', ['-B', '-c', `
import sys
sys.path.insert(0, 'tests')
from test_inventory_groups import observation
from test_report import snapshot
from palma_scan.report import render_report
data = snapshot()
data['findings'] = []
data['observations'] = [
    observation('local', 'mcp', 'fixture-tools', execution='local', copyCount=3),
    observation('remote', 'mcp', 'fixture-tools', 'cursor', governedBy='palma-gateway'),
    observation('skill', 'skill', 'fixture-helper', 'cursor', digest='a'),
]
print(render_report(data, {}))
`], { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
assert.equal(rendered.status, 0, rendered.stderr);
const dom = new JSDOM(rendered.stdout, { runScripts: 'outside-only', url: 'https://offline.invalid/' });
const { window } = dom;
const { document } = window;
for (const api of ['fetch', 'XMLHttpRequest', 'WebSocket']) {
  window[api] = () => { throw new Error('Unexpected outbound API: ' + api); };
}
window.HTMLElement.prototype.scrollIntoView = function () {};
window.eval(document.querySelector('script').textContent);
const group = document.getElementById('inventory-mcp');
assert.ok(group, 'MCP overview exists');
const rows = group.querySelectorAll('.inventory-row');
assert.equal(rows.length, 1, 'one row per declared server name');
const row = rows[0];
const declarations = row.querySelector('.inventory-declarations');
assert.match(declarations.querySelector('summary').textContent, /4 declarations/);
assert.equal(declarations.querySelectorAll('.declaration-row').length, 2, 'configuration variants remain separate');
assert.equal(row.querySelectorAll('.inventory-client-tag').length, 2, 'both clients are tagged');
const search = document.getElementById('inventory-search');
search.value = 'cursor';
search.dispatchEvent(new window.Event('input', { bubbles: true }));
assert.equal(group.open, true);
assert.equal(row.hidden, false, 'client search finds the grouped server');
declarations.querySelector('summary').click();
assert.equal(declarations.open, true, 'declaration evidence expands');
assert.match(declarations.textContent, /Runs locally/);
assert.match(declarations.textContent, /Through Palma gateway/);
const target = row.querySelector('.inventory-client-tag').getAttribute('href');
search.value = 'missing-fixture';
search.dispatchEvent(new window.Event('input', { bubbles: true }));
window.location.hash = target;
window.dispatchEvent(new window.Event('hashchange'));
assert.equal(search.value, '');
assert.equal(document.querySelector(target).open, true, 'client badge destination reveals client details');
console.log('PASS: grouped name, declaration count and variants, client search, evidence expansion and client links.');
dom.window.close();
