// Shared sidebar behavior for the docs and self-contained benchmark reports.
(() => {
  const root = document.documentElement;
  const sidebar = document.querySelector('#mdbook-sidebar, #benchmark-sidebar');
  if (!sidebar) return;
  const mobile = matchMedia('(max-width:619px)');
  const checkbox = document.getElementById('mdbook-sidebar-toggle-anchor');
  const oldToggle = document.getElementById('mdbook-sidebar-toggle');
  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'site-contents-toggle';
  toggle.textContent = 'Contents';
  toggle.setAttribute('aria-controls', sidebar.id);
  if (oldToggle) {
    toggle.id = oldToggle.id;
    oldToggle.replaceWith(toggle);
  } else {
    document.querySelector('.site-header').append(toggle);
  }
  sidebar.classList.add('site-sidebar');
  root.classList.add('site-sidebar-ready', 'sidebar-enhanced');
  const oldHandle = document.getElementById('mdbook-sidebar-resize-handle');
  const handle = document.createElement('div');
  handle.className = 'site-sidebar-resize';
  handle.tabIndex = 0;
  handle.setAttribute('role', 'separator');
  handle.setAttribute('aria-orientation', 'vertical');
  handle.setAttribute('aria-label', 'Contents width');
  handle.setAttribute('aria-controls', sidebar.id);
  handle.title = 'Drag to resize; use arrow keys, or double-click to reset';
  if (oldHandle) oldHandle.replaceWith(handle);
  else sidebar.append(handle);

  function read(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  function save(key, value) {
    try { localStorage.setItem(key, String(value)); } catch { /* Storage is optional. */ }
  }
  let desktopOpen = read('mdbook-sidebar') !== 'hidden';
  const stored = Number(read('syq-sidebar-width'));
  let preferredWidth = Number.isFinite(stored) && stored >= 240 && stored <= 480 ? stored : 300;
  function applyWidth() {
    const max = Math.min(480, innerWidth - (mobile.matches ? 32 : 100));
    const width = Math.min(preferredWidth, max);
    root.style.setProperty('--site-sidebar-width', width + 'px');
    root.style.setProperty('--sidebar-target-width', width + 'px');
    handle.setAttribute('aria-valuemin', String(Math.min(240, max)));
    handle.setAttribute('aria-valuemax', String(max));
    handle.setAttribute('aria-valuenow', String(Math.round(width)));
  }
  function resize(width) {
    preferredWidth = Math.round(Math.max(240, Math.min(480, innerWidth - 100, width)));
    save('syq-sidebar-width', preferredWidth);
    applyWidth();
  }
  function sync() {
    const open = root.classList.contains('sidebar-visible');
    if (checkbox) checkbox.checked = open;
    sidebar.style.removeProperty('display');
    sidebar.inert = !open;
    sidebar.setAttribute('aria-hidden', String(!open));
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', (open ? 'Hide' : 'Show') + ' contents');
    sidebar.querySelectorAll('a').forEach(link => link.removeAttribute('tabindex'));
    if (!mobile.matches) desktopOpen = open;
    save('mdbook-sidebar', desktopOpen ? 'visible' : 'hidden');
  }
  function setOpen(open) {
    root.classList.toggle('sidebar-visible', open);
    sync();
  }
  applyWidth();
  setOpen(!mobile.matches && desktopOpen);
  toggle.addEventListener('click', () => setOpen(!root.classList.contains('sidebar-visible')));
  // Reconcile mdBook's native touch gestures with the shared state and checkbox.
  new MutationObserver(sync).observe(root, {attributes: true, attributeFilter: ['class']});
  mobile.addEventListener('change', () => {
    applyWidth();
    setOpen(!mobile.matches && desktopOpen);
  });
  window.addEventListener('resize', applyWidth);
  sidebar.addEventListener('click', event => {
    if (mobile.matches && event.target.closest('a')) setOpen(false);
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && mobile.matches && root.classList.contains('sidebar-visible')) {
      setOpen(false);
      toggle.focus();
    }
  });
  let pointer = null;
  handle.addEventListener('pointerdown', event => {
    if (event.button !== 0 || mobile.matches) return;
    event.preventDefault();
    pointer = event.pointerId;
    handle.setPointerCapture(pointer);
    root.classList.add('site-sidebar-resizing');
  });
  handle.addEventListener('pointermove', event => {
    if (event.pointerId === pointer) resize(event.clientX);
  });
  function stop() {
    pointer = null;
    root.classList.remove('site-sidebar-resizing');
  }
  handle.addEventListener('pointerup', stop);
  handle.addEventListener('pointercancel', stop);
  handle.addEventListener('lostpointercapture', stop);
  handle.addEventListener('dblclick', () => resize(300));
  handle.addEventListener('keydown', event => {
    const delta = event.shiftKey ? 40 : 10;
    if (event.key === 'ArrowLeft') resize(preferredWidth - delta);
    else if (event.key === 'ArrowRight') resize(preferredWidth + delta);
    else if (event.key === 'Home') resize(300);
    else return;
    event.preventDefault();
    event.stopPropagation();
  });
  // Match the docs' edge-swipe gesture on benchmark pages too.
  let contact = null;
  document.addEventListener('touchstart', event => {
    contact = {x: event.touches[0].clientX, time: Date.now()};
  }, {passive: true});
  document.addEventListener('touchmove', event => {
    if (!contact || !mobile.matches) return;
    const x = event.touches[0].clientX;
    if (Date.now() - contact.time < 250 && Math.abs(x - contact.x) >= 150) {
      if (x > contact.x && contact.x < Math.min(innerWidth * .25, 300)) setOpen(true);
      else if (x < contact.x && x < 300) setOpen(false);
      contact = null;
    }
  }, {passive: true});
})();
