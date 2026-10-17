// attention.js: red dots on nav items for pending agent tasks, plus the agents queue.
// Polls GET /api/agent-attention on load and every 30s. Pauses while the tab is hidden.
// Any page can ask for an immediate refresh: window.dispatchEvent(new Event('attention-refresh')).
(function () {
  'use strict';
  var API = '/api/agent-attention';
  var INTERVAL_MS = 30000;
  var PORTAL_ORDER = ['alerts', 'rules', 'ingestion', 'logs'];
  var PORTAL_LABEL = {alerts: 'Alerts', rules: 'Rules', ingestion: 'Ingestion', logs: 'Logs'};
  var timer = null;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function applyDots(byPortal) {
    var dots = document.querySelectorAll('.attn-dot[data-portal]');
    for (var i = 0; i < dots.length; i++) {
      var dot = dots[i];
      var n = Number((byPortal || {})[dot.getAttribute('data-portal')]) || 0;
      var msg = n > 0 ? n + ' agent task(s) need attention' : '';
      dot.hidden = n <= 0;
      dot.title = msg;
      if (msg) dot.setAttribute('aria-label', msg);
      else dot.removeAttribute('aria-label');
    }
  }

  function refresh() {
    if (document.hidden) return;
    fetch(API, {cache: 'no-store'})
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) return;
        applyDots(data.by_portal);
        renderQueue(data);
      })
      .catch(function (err) { console.debug('attention refresh failed', err); });
  }

  function start() { if (timer === null) timer = setInterval(refresh, INTERVAL_MS); }
  function stop() { if (timer !== null) { clearInterval(timer); timer = null; } }
  function onVisibility() {
    if (document.hidden) { stop(); return; }
    refresh();
    start();
  }

  document.addEventListener('visibilitychange', onVisibility);
  window.addEventListener('attention-refresh', refresh);
  window.attentionRefresh = refresh;
  refresh();
  if (!document.hidden) start();

  function pageHref(item) {
    var target = encodeURIComponent(item.target || '');
    if (item.portal === 'alerts') {
      return item.kind === 'injection_review' && item.target ? '/alerts?preview=' + target : '/alerts';
    }
    if (item.portal === 'rules') return item.target ? '/rules/' + target : '/rules';
    if (item.portal === 'ingestion') return '/ingestion';
    if (item.portal === 'logs') return '/logs';
    return '/agents';
  }

  function showError(btn, msg) {
    var wrap = btn.parentNode;
    var old = wrap.querySelector('.attn-error');
    if (old) wrap.removeChild(old);
    wrap.appendChild(el('span', 'attn-error', msg));
    btn.disabled = false;
  }

  function decide(recId, verb, btn) {
    btn.disabled = true;
    var url = '/api/agent-panel/recommendations/' + encodeURIComponent(recId) + '/' + verb;
    fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'})
      .then(function (r) { return r.json().then(function (body) { return {ok: r.ok, body: body}; }); })
      .then(function (res) {
        if (res.ok) { window.dispatchEvent(new Event('attention-refresh')); return; }
        showError(btn, res.body.error || 'failed');
      })
      .catch(function () { showError(btn, 'request failed'); });
  }

  function actionButton(label, item, verb) {
    var btn = el('button', 'btn btn-sm', label);
    btn.type = 'button';
    btn.disabled = !item.allowed;
    if (!item.allowed) btn.title = item.blocked_reason || 'not allowed';
    btn.addEventListener('click', function () { decide(item.rec_id, verb, btn); });
    return btn;
  }

  function rowNode(item) {
    var row = el('div', 'attn-row');
    var text = el('div', 'attn-text');
    var link = el('a', 'attn-link', item.title || item.id);
    link.href = pageHref(item);
    text.appendChild(link);
    text.appendChild(el('div', 'attn-why muted', item.rationale || item.kind));
    row.appendChild(text);
    row.appendChild(el('span', 'pill pill-status-open', item.kind));
    if (item.rec_id) {
      var wrap = el('div', 'attn-actions');
      wrap.appendChild(actionButton('Approve', item, 'approve'));
      wrap.appendChild(actionButton('Reject', item, 'reject'));
      row.appendChild(wrap);
    } else {
      row.appendChild(el('span', 'attn-why muted', item.blocked_reason || ''));
    }
    return row;
  }

  function groupNode(portal, group) {
    var wrap = el('div', 'attn-group');
    wrap.appendChild(el('h3', 'attn-group-title', PORTAL_LABEL[portal] + ' (' + group.length + ')'));
    group.forEach(function (item) { wrap.appendChild(rowNode(item)); });
    return wrap;
  }

  function renderQueue(data) {
    var box = document.getElementById('attention-queue-list');
    if (!box) return;
    var items = data.items || [];
    box.textContent = '';
    if (items.length === 0) {
      box.appendChild(el('p', 'muted', 'Nothing needs your attention.'));
      return;
    }
    PORTAL_ORDER.forEach(function (portal) {
      var group = items.filter(function (it) { return it.portal === portal; });
      if (group.length) box.appendChild(groupNode(portal, group));
    });
    if (data.total > items.length) {
      box.appendChild(el('p', 'muted', 'Showing ' + items.length + ' of ' + data.total + ' tasks.'));
    }
  }
})();
