/* alerts preview drawer: GET /api/alerts/{id}/preview. Needs alerts.js. */
(function () {
  'use strict';
  var U = window.AlertsUI;
  var drawer, body, title;

  function section(name) {
    var s = U.el('div', 'drawer-section');
    s.appendChild(U.el('div', 'drawer-label', name));
    return s;
  }

  function selector(options, labels, value, onPick) {
    var s = U.el('select', 'select select-sm');
    options.forEach(function (o) {
      var op = U.el('option', '', labels ? labels[o] : o);
      op.value = o; if (o === value) { op.selected = true; }
      s.appendChild(op);
    });
    s.addEventListener('change', function () { onPick(s.value, s); });
    return s;
  }

  function render(d) {
    title.textContent = '#' + (d.alert_number || '?') + '  ' + (d.title || '');
    body.textContent = '';
    var ctl = section('Triage');
    var send = function (field) {
      return function (v, s) {
        s.disabled = true;
        U.setField(d.alert_id, field, v).then(function () { U.refreshCharts(); location.reload(); })
          .catch(function (e) { U.flash(e.message, true); s.disabled = false; });
      };
    };
    ctl.appendChild(selector(U.SEVERITIES, null, d.severity, send('severity')));
    ctl.appendChild(selector(Object.keys(U.STATUS_LABELS), U.STATUS_LABELS, d.status, send('status')));
    body.appendChild(ctl);
    var info = section('Rule');
    if (d.rule_id) {
      var a = U.el('a', 'link', d.rule_name || d.rule_id);
      a.href = '/rules/' + encodeURIComponent(d.rule_id);
      info.appendChild(a);
    }
    if (d.description) { info.appendChild(U.el('p', 'muted', d.description)); }
    body.appendChild(info);
    body.appendChild(listSection('Entities', d.entities, function (e) { return (e.type || '') + ': ' + (e.value || ''); }));
    body.appendChild(listSection('MITRE', ((d.mitre || {}).techniques || []).concat((d.mitre || {}).tactics || []), String));
    body.appendChild(listSection('Evidence (first rows)', d.evidence, function (r) { return JSON.stringify(r).slice(0, 240); }));
    body.appendChild(listSection('Comments', d.comments, function (c) { return (c.author || '') + ': ' + (c.body || ''); }));
    var open = U.el('a', 'btn btn-primary', 'Open full page');
    open.href = '/alerts/' + encodeURIComponent(d.alert_id);
    body.appendChild(open);
    document.dispatchEvent(new CustomEvent('alert-preview', {detail: d}));
  }

  function listSection(name, items, fmt) {
    var s = section(name);
    if (!items || !items.length) { s.appendChild(U.el('div', 'muted', 'none')); return s; }
    items.forEach(function (it) { s.appendChild(U.el('div', 'drawer-item', fmt(it))); });
    return s;
  }

  function open(id) {
    drawer.hidden = false;
    body.textContent = 'Loading...';
    fetch('/api/alerts/' + encodeURIComponent(id) + '/preview').then(function (r) {
      return r.json().then(function (d) { if (!r.ok) { throw new Error(d.error || r.status); } return d; });
    }).then(render).catch(function (e) { body.textContent = 'Could not load preview: ' + e.message; });
    history.replaceState(null, '', '?preview=' + encodeURIComponent(id));
  }

  function close() {
    drawer.hidden = true;
    history.replaceState(null, '', location.pathname);
    var panel = document.getElementById('agent-panel');
    if (panel && panel._agentPanel) { panel._agentPanel.destroy(); }
  }

  // agent_panel.js is loaded first; mount the triage panel for the previewed alert.
  document.addEventListener('alert-preview', function (e) {
    var panel = document.getElementById('agent-panel');
    if (panel && window.AgentPanel && e.detail && e.detail.alert_id) {
      window.AgentPanel.mount(panel, 'alert', e.detail.alert_id);
    }
  });

  document.addEventListener('DOMContentLoaded', function () {
    drawer = document.getElementById('alert-drawer');
    if (!drawer) { return; }
    body = document.getElementById('drawer-body');
    title = document.getElementById('drawer-title');
    document.getElementById('drawer-close').addEventListener('click', close);
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { close(); } });
    document.addEventListener('click', function (e) {
      var row = e.target.closest ? e.target.closest('tr.alert-row') : null;
      if (!row || e.target.closest('select, a, input, button')) { return; }
      open(row.getAttribute('data-alert-id'));
    });
    var pre = (document.getElementById('alerts-page') || {}).dataset;
    if (pre && pre.previewId) { open(pre.previewId); }
  });
})();
