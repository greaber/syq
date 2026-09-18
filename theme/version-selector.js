(() => {
  const selector = document.getElementById('docs-version-select');
  if (!selector) return;
  const current = Array.from(selector.options).find(option => option.defaultSelected);
  // Back/Forward can restore the choice that navigated away from this page.
  window.addEventListener('pageshow', () => { selector.value = current.value; });
  // mdBook's chapter/search shortcuts must not intercept native select keys.
  selector.addEventListener('keydown', event => event.stopPropagation());
  selector.addEventListener('change', () => {
    const option = selector.selectedOptions[0];
    const target = new URL(option.value, window.location.origin);
    if (option.dataset.samePage === 'true') {
      target.search = window.location.search;
      target.hash = window.location.hash;
    }
    window.location.assign(target.href);
  });
})();
