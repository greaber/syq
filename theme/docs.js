(() => {
// The header markup is shared verbatim with syq-bench.
document.querySelector('.site-nav [data-site="docs"]').setAttribute('aria-current', 'page');
// mdBook owns the chapter links; add a section label without forking its template.
const sidebar = document.querySelector('.sidebar-scrollbox');
const label = document.createElement('p');
label.className = 'site-section';
label.textContent = 'Documentation';
sidebar.prepend(label);
})();
