// Offline DOM regression using the real renderer and a synthetic client-only snapshot.
// PALMA_TEST_PYTHON=python3 NODE_PATH=/path/to/jsdom/node_modules node tests/report-client-only.cjs
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '..');
const rendered = spawnSync(process.env.PALMA_TEST_PYTHON || 'python3', ['-B', '-c', `
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from palma_scan.report import render_report
from palma_scan.model import summarize
snapshot = json.loads(Path('examples/snapshot.json').read_text())
client = next(item for item in snapshot['observations'] if item['kind'] == 'client')
client.update(client='claude-code', name='claude-code')
client['details'].update(version='2.1.10', installationState='installed', processObserved=True)
snapshot['observations'] = [client]
snapshot['findings'] = []
print(render_report(snapshot, summarize(snapshot)))
`], { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
assert.equal(rendered.status, 0, rendered.stderr);
const dom = new JSDOM(rendered.stdout, { runScripts: 'outside-only' });
const { window } = dom;
const { document } = window;
for (const api of ['fetch', 'XMLHttpRequest', 'WebSocket']) {
  window[api] = () => { throw new Error('Unexpected outbound API: ' + api); };
}
window.HTMLElement.prototype.scrollIntoView = function () {};
window.eval(document.querySelector('script').textContent);
const groups = [...document.querySelectorAll('.inventory-group')];
assert.equal(groups.length, 1);
assert.equal(document.querySelectorAll('.inventory-row').length, 0);
const group = groups[0];
const input = document.getElementById('inventory-search');
const empty = document.getElementById('inventory-no-results');
function search(query) {
  input.value = query;
  input.dispatchEvent(new window.Event('input', { bubbles: true }));
}
assert.equal(group.hidden, false);
for (const query of ['claude code', '2.1.10', 'installed']) {
  search(query);
  assert.equal(group.hidden, false, 'client facts remain searchable: ' + query);
  assert.equal(empty.hidden, true);
}
search('missing-fixture');
assert.equal(group.hidden, true);
assert.equal(empty.hidden, false, 'client-only reports show an empty search result');
document.getElementById('clear-inventory-search').click();
assert.equal(group.hidden, false, 'reset restores a client without member rows');
assert.equal(group.open, false, 'reset restores the original disclosure state');
assert.equal(empty.hidden, true);
search('missing-fixture');
window.location.hash = group.id;
window.dispatchEvent(new window.Event('hashchange'));
assert.equal(group.hidden, false, 'client anchors reveal client-only groups');
assert.equal(group.open, true);
console.log('PASS: client-only search by name/version/state, no results, reset and anchor reveal.');
dom.window.close();
