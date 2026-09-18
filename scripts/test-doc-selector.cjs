const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../theme/version-selector.js'), 'utf8');

function browser() {
  const handlers = {};
  const selector = {
    value: '/syq/v0.6.0/reference.html',
    options: [{ value: '/syq/v0.6.0/reference.html', defaultSelected: true }],
    addEventListener: (name, callback) => { handlers[name] = callback; },
  };
  const location = { origin: 'https://greaber.github.io', search: '?search=copy', hash: '#resume',
    assign: url => { location.destination = url; } };
  vm.runInNewContext(script, { URL, document: { getElementById: () => selector },
    window: { location, addEventListener: (name, callback) => { handlers[name] = callback; } } });
  return { selector, handlers, location };
}

test('Back/Forward restores the displayed version, allowing the same destination again', () => {
  const { selector, handlers, location } = browser();
  selector.selectedOptions = [{ value: '/syq/master/reference.html', dataset: { samePage: 'true' } }];
  selector.value = selector.selectedOptions[0].value;
  handlers.change();
  assert.equal(location.destination, 'https://greaber.github.io/syq/master/reference.html?search=copy#resume');
  handlers.pageshow({ persisted: true });
  assert.equal(selector.value, '/syq/v0.6.0/reference.html');
  selector.value = '/syq/master/reference.html';
  handlers.pageshow({ persisted: false });
  assert.equal(selector.value, '/syq/v0.6.0/reference.html');
});

test('a missing page falls back without its unrelated query or fragment', () => {
  const { selector, handlers, location } = browser();
  selector.selectedOptions = [{ value: '/syq/v0.2.0/index.html', dataset: { samePage: 'false' } }];
  handlers.change();
  assert.equal(location.destination, 'https://greaber.github.io/syq/v0.2.0/index.html');
});
