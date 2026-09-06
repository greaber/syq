// Shared header controls. Search uses each renderer's own document index.
(() => {
  const root = document.documentElement;
  const header = document.querySelector('.site-header');
  const contents = document.querySelector('.site-contents-toggle');
  const nativeTheme = document.getElementById('mdbook-theme-toggle');
  const nativeSearch = document.getElementById('mdbook-search-toggle');
  const controls = document.createElement('div');
  controls.className = 'site-controls';
  header.append(controls);
  controls.append(contents);
  function button(text, label) {
    const el = document.createElement('button');
    el.type = 'button';
    el.textContent = text;
    el.setAttribute('aria-label', label);
    controls.append(el);
    return el;
  }
  const theme = button('Theme', 'Choose color theme');
  const popup = document.createElement('div');
  popup.id = 'site-theme-options';
  popup.className = 'site-theme-options';
  popup.hidden = true;
  popup.setAttribute('role', 'group');
  popup.setAttribute('aria-label', 'Color theme');
  theme.setAttribute('aria-controls', popup.id);
  theme.setAttribute('aria-expanded', 'false');
  controls.append(popup);
  const search = button('Search', 'Search this site');
  search.setAttribute('aria-keyshortcuts', '/');
  search.setAttribute('aria-expanded', 'false');
  function read(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  const legacy = read('mdbook-theme');
  let selected = read('syq-color-theme') || (['coal','navy','ayu'].includes(legacy) ? 'dark' : ['light','rust'].includes(legacy) ? 'light' : 'auto');
  if (!['auto','light','dark'].includes(selected)) selected = 'auto';
  const osTheme = matchMedia('(prefers-color-scheme:dark)');
  function applyTheme(value) {
    selected = value;
    try { localStorage.setItem('syq-color-theme', value); } catch { /* Optional. */ }
    const actual = value === 'auto' ? (osTheme.matches ? 'dark' : 'light') : value;
    root.dataset.theme = actual;
    if (nativeTheme) document.getElementById('mdbook-theme-' + ({auto:'default_theme',light:'light',dark:'navy'}[value])).click();
    for (const option of popup.querySelectorAll('button')) option.setAttribute('aria-pressed', String(option.dataset.theme === value));
  }
  function closeTheme() {
    popup.hidden = true;
    theme.setAttribute('aria-expanded', 'false');
  }
  for (const [value, label] of [['auto','System'],['light','Light'],['dark','Dark']]) {
    const option = document.createElement('button');
    option.type = 'button';
    option.textContent = label;
    option.dataset.theme = value;
    option.addEventListener('click', () => {applyTheme(value); closeTheme(); theme.focus();});
    popup.append(option);
  }
  theme.addEventListener('click', () => {
    popup.hidden = !popup.hidden;
    theme.setAttribute('aria-expanded', String(!popup.hidden));
    if (!popup.hidden) popup.querySelector('[aria-pressed="true"]').focus();
  });
  applyTheme(selected);
  osTheme.addEventListener('change', () => applyTheme(selected));
  window.addEventListener('storage', event => {
    if (event.key === 'syq-color-theme' && ['auto','light','dark'].includes(event.newValue)) applyTheme(event.newValue);
  });

  let panel, input;
  if (nativeSearch) {
    panel = document.getElementById('mdbook-search-wrapper');
    input = document.getElementById('mdbook-searchbar');
    panel.classList.add('site-search-panel');
    input.placeholder = 'Search this site';
    input.setAttribute('aria-label', 'Search this site');
    search.setAttribute('aria-controls', panel.id);
    new MutationObserver(() => search.setAttribute('aria-expanded', nativeSearch.getAttribute('aria-expanded')))
      .observe(nativeSearch, {attributes:true, attributeFilter:['aria-expanded']});
    search.addEventListener('click', () => nativeSearch.click());
  } else {
    panel = document.createElement('section');
    panel.id = 'site-search';
    panel.className = 'site-search-panel';
    panel.hidden = true;
    input = document.createElement('input');
    input.type = 'search';
    input.placeholder = 'Search this site';
    input.setAttribute('aria-label', 'Search this site');
    const status = document.createElement('p');
    status.setAttribute('aria-live','polite');
    const results = document.createElement('ul');
    panel.append(input, status, results);
    document.querySelector('main').prepend(panel);
    const index = JSON.parse(document.getElementById('site-search-index').textContent);
    input.addEventListener('input', () => {
      const terms = input.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
      results.replaceChildren();
      const found = terms.length ? index.filter(entry => terms.every(term => entry.text.toLocaleLowerCase().includes(term))) : [];
      status.textContent = terms.length ? found.length + (found.length === 1 ? ' result' : ' results') : '';
      for (const entry of found) {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = entry.href;
        a.textContent = entry.title;
        li.append(a);
        results.append(li);
      }
    });
    search.setAttribute('aria-controls', panel.id);
    search.addEventListener('click', () => {
      panel.hidden = !panel.hidden;
      search.setAttribute('aria-expanded', String(!panel.hidden));
      if (!panel.hidden) input.focus();
    });
  }
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      if (!popup.hidden) {closeTheme(); theme.focus();}
      if (search.getAttribute('aria-expanded') === 'true') {search.click();search.focus();}
    }
    if (!nativeSearch && event.key === '/' && !event.ctrlKey && !event.metaKey &&
        !event.altKey && !event.target.closest('input,textarea,[contenteditable="true"]')) {
      event.preventDefault();
      if (panel.hidden) search.click();
      else input.focus();
    }
  });
  document.addEventListener('click', event => {
    if (!controls.contains(event.target)) closeTheme();
  });
  if (nativeTheme) {
    // Keep the native theme/search handlers as adapters, but show one shared UI.
    document.querySelector('.docs-controls').hidden = true;
    document.querySelector('.docs-controls').setAttribute('aria-hidden','true');
  }
})();
