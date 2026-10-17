/* alerts list: inline row edits + bulk actions. Needs alerts.js. */
(function () {
  'use strict';
  var U = window.AlertsUI;

  function onRowSelect(sel) {
    var id = sel.getAttribute('data-alert-id');
    var field = sel.getAttribute('data-alert-field');
    var prev = sel.getAttribute('data-prev') || sel.getAttribute('data-status') || '';
    sel.disabled = true;
    U.setField(id, field, sel.value).then(function () {
      sel.setAttribute('data-prev', sel.value);
      if (field === 'status') { sel.setAttribute('data-status', sel.value); }
      if (field === 'severity') { sel.className = 'select select-sm sev-select sev-' + sel.value; }
      U.flash('Updated ' + field + ' to ' + sel.value, false);
      return U.refreshCharts();
    }).catch(function (e) {
      if (prev) { sel.value = prev; }
      U.flash('Could not update: ' + e.message, true);
    }).then(function () { sel.disabled = false; });
  }

  function selectedIds() {
    var out = [];
    document.querySelectorAll('.alert-sel:checked').forEach(function (c) { out.push(c.value); });
    return out;
  }

  function updateCount() {
    var n = selectedIds().length;
    var c = document.getElementById('bulk-count');
    if (c) { c.textContent = n + ' selected'; }
  }

  function bulk(field, selId) {
    var value = document.getElementById(selId).value;
    var ids = selectedIds();
    if (!value || !ids.length) { U.flash('Pick rows and a value first', true); return; }
    var done = 0;
    var chain = Promise.resolve();
    ids.forEach(function (id) {
      chain = chain.then(function () { return U.setField(id, field, value).then(function () { done++; }); });
    });
    chain.then(function () { location.reload(); })
      .catch(function (e) { U.flash('Bulk stopped after ' + done + '/' + ids.length + ': ' + e.message, true); });
  }

  document.addEventListener('change', function (ev) {
    var t = ev.target;
    if (t.matches && t.matches('select[data-alert-field]')) { onRowSelect(t); }
    if (t.matches && t.matches('select[data-autosubmit]')) { t.form.submit(); }
    if (t.id === 'select-all') {
      document.querySelectorAll('.alert-sel').forEach(function (c) { c.checked = t.checked; });
    }
    if (t.classList && (t.classList.contains('alert-sel') || t.id === 'select-all')) { updateCount(); }
  });

  document.addEventListener('click', function (ev) {
    if (ev.target.id === 'bulk-status-apply') { bulk('status', 'bulk-status'); }
    if (ev.target.id === 'bulk-severity-apply') { bulk('severity', 'bulk-severity'); }
  });
})();
