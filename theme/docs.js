(() => {
// The header markup is shared verbatim with syq-bench.
document.querySelector('.site-nav [data-site="docs"]').setAttribute('aria-current', 'page');

// Move the existing nodes so mdBook keeps its listeners, labels and shortcuts.
const controls = document.querySelector('#mdbook-menu-bar .left-buttons');
controls.classList.add('docs-controls');
document.querySelector('.site-header').append(controls);

const pageActions = document.createElement('nav');
pageActions.className = 'docs-page-actions';
pageActions.setAttribute('aria-label', 'Page tools');
for (const [selector, label] of [
  ['#print-button', 'Print this book'],
  ['#git-edit-button', 'Edit this page'],
]) {
  const link = document.querySelector(selector)?.closest('a');
  if (link) {
    link.textContent = label;
    pageActions.append(link);
  }
}
document.querySelector('.content main').append(pageActions);
document.documentElement.classList.add('docs-compact-header');
})();
