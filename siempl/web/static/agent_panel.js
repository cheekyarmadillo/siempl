/* Agent panel component. AgentPanel.mount(container, scope, targetId) renders GET /api/agent-panel/{scope}/{id}
 * into the container and re-polls (4s while running, 15s otherwise, paused while the tab is hidden).
 * AgentPanel.mountAll(root) mounts every [data-agent-scope][data-agent-target] element under root.
 * Builds DOM with createElement + textContent only, never markup strings. No libraries. Not for agent logic. */
(function () {
  'use strict';
  var FAST_MS = 4000;
  var SLOW_MS = 15000;
  var AWAIT_RUN_MS = 120000;
  var CAPS = [['can_close', 'close'], ['can_escalate', 'escalate'], ['can_remediate', 'remediate'],
    ['can_create_temp_rules', 'temp rules']];

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = String(text); }
    return n;
  }

  function fmtTime(v) {
    return v ? String(v).replace('T', ' ').slice(0, 19) : '-';
  }

  function fmtCost(v) {
    return '$' + Number(v || 0).toFixed(4);
  }

  function safeClass(v) {
    return String(v || '').toLowerCase().replace(/[^a-z_-]/g, '');
  }

  function request(method, url, body) {
    var opts = { method: method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(url, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        return { ok: r.ok, status: r.status, data: data || {} };
      });
    });
  }

  function reasonOf(res) {
    var d = res.data || {};
    return d.blocked_reason || d.error || d.detail || ('HTTP ' + res.status);
  }

  function stillRunning(st) {
    var s = st.state || {};
    if (s.running) { return true; }
    if (!st.awaitUntil || Date.now() > st.awaitUntil) { return false; }
    var lr = s.last_run;
    if (lr && lr.run_id !== st.prevRunId) { st.awaitUntil = 0; return false; }
    return true;
  }

  function schedule(st) {
    clearTimeout(st.timer);
    if (st.dead || document.hidden) { return; }
    var ms = stillRunning(st) ? FAST_MS : SLOW_MS;
    st.timer = setTimeout(function () { refresh(st); }, ms);
  }
  function refresh(st) {
    clearTimeout(st.timer);
    if (st.dead || document.hidden) { return Promise.resolve(); }
    var url = '/api/agent-panel/' + encodeURIComponent(st.scope) + '/' + encodeURIComponent(st.targetId);
    return request('GET', url).then(function (res) {
      if (st.dead) { return; }
      var wasRunning = !!(st.state && st.state.running);
      st.error = res.ok ? null : reasonOf(res);
      st.state = res.ok ? res.data : null;
      if (wasRunning && !(st.state && st.state.running)) { window.dispatchEvent(new Event('attention-refresh')); }
      renderPanel(st);
      schedule(st);
    }).catch(function (e) {
      if (st.dead) { return; }
      st.error = 'Could not reach the agent API: ' + e.message;
      renderPanel(st);
      schedule(st);
    });
  }
  function stateOf(s) {
    if (!s.enabled || !s.ai_enabled) { return 'disabled'; }
    if (s.running) { return 'running'; }
    if ((s.pending || []).length) { return 'needs approval'; }
    return 'idle';
  }

  function headerEl(st, s) {
    var key = stateOf(s);
    var head = el('div', 'agent-head');
    head.appendChild(el('strong', 'agent-name', s.agent || 'agent'));
    head.appendChild(el('span', 'pill agent-state agent-state-' + key.split(' ').join('-'), key));
    var act = s.actions || {};
    var btn = el('button', 'btn btn-sm agent-run', s.running || st.busy ? 'Running...' : 'Run');
    btn.type = 'button';
    btn.disabled = !act.can_run || st.busy;
    if (!act.can_run && act.run_blocked_reason) { btn.title = act.run_blocked_reason; }
    btn.addEventListener('click', function () { runAgent(st); });
    head.appendChild(btn);
    if (!act.can_run && act.run_blocked_reason) {
      head.appendChild(el('span', 'agent-reason muted', act.run_blocked_reason));
    }
    return head;
  }
  function policyEl(p) {
    var wrap = el('div', 'agent-policy');
    wrap.appendChild(el('span', 'muted', 'Policy: ' + (p.mode || 'unknown')));
    CAPS.forEach(function (c) {
      var on = !!p[c[0]];
      wrap.appendChild(el('span', 'chip agent-cap ' + (on ? 'agent-cap-on' : 'agent-cap-off'),
        (on ? '' : 'no ') + c[1]));
    });
    return wrap;
  }

  function noticeEl(st) {
    var cls = st.notice.ok ? 'agent-notice agent-notice-ok' : 'agent-notice agent-notice-err';
    var n = el('div', cls, st.notice.text);
    n.setAttribute('role', 'status');
    return n;
  }

  function injectionEl(inj) {
    var box = el('div', 'agent-injection');
    box.setAttribute('role', 'alert');
    box.appendChild(el('strong', '', 'Possible prompt injection in telemetry - held for human review'));
    var list = el('ul', 'agent-findings');
    (inj.findings || []).forEach(function (f) {
      var txt = (f && typeof f === 'object') ? String(f.rule || '?') + (f.excerpt ? ': ' + f.excerpt : '') : String(f);
      list.appendChild(el('li', '', txt.slice(0, 160)));
    });
    box.appendChild(list);
    return box;
  }
  function outputEl(st, text) {
    var d = document.createElement('details');
    d.className = 'agent-output';
    d.open = st.outputOpen;
    d.appendChild(el('summary', '', 'Output'));
    d.appendChild(el('pre', 'agent-pre', text));
    d.addEventListener('toggle', function () { st.outputOpen = d.open; });
    return d;
  }

  function lastRunEl(st, lr) {
    var box = el('div', 'agent-lastrun');
    box.appendChild(el('div', 'agent-label', 'Last run'));
    if (!lr) { box.appendChild(el('div', 'muted', 'No runs yet for this target.')); return box; }
    var row = el('div', 'agent-lastrun-row');
    row.appendChild(el('span', 'pill pill-status-' + safeClass(lr.status), lr.status || 'unknown'));
    row.appendChild(el('span', 'muted', fmtTime(lr.finished_at || lr.started_at)));
    row.appendChild(el('span', 'muted', fmtCost(lr.cost_usd)));
    box.appendChild(row);
    if (lr.summary) { box.appendChild(el('div', 'agent-summary', lr.summary)); }
    if (lr.error) { box.appendChild(el('div', 'agent-error', 'Error: ' + lr.error)); }
    if (lr.output) { box.appendChild(outputEl(st, lr.output)); }
    return box;
  }
  function recEl(st, it) {
    var card = el('div', 'agent-rec');
    var top = el('div', 'agent-rec-top');
    top.appendChild(el('strong', '', it.title || it.id));
    top.appendChild(el('span', 'chip agent-kind', it.kind || 'recommendation'));
    card.appendChild(top);
    if (it.rationale) { card.appendChild(el('p', 'muted agent-rationale', it.rationale)); }
    var btns = el('div', 'btn-row');
    var ap = el('button', 'btn btn-sm btn-primary', 'Approve');
    ap.type = 'button';
    ap.disabled = !it.allowed || st.busy;
    if (!it.allowed && it.blocked_reason) { ap.title = it.blocked_reason; }
    ap.addEventListener('click', function () { decide(st, it.id, 'approve'); });
    var rj = el('button', 'btn btn-sm', 'Reject');
    rj.type = 'button';
    rj.disabled = st.busy;
    rj.addEventListener('click', function () { decide(st, it.id, 'reject'); });
    btns.appendChild(ap);
    btns.appendChild(rj);
    card.appendChild(btns);
    if (!it.allowed && it.blocked_reason) {
      card.appendChild(el('div', 'agent-reason', 'Approve blocked: ' + it.blocked_reason));
    }
    return card;
  }

  function pendingEl(st, items) {
    var box = el('div', 'agent-pending');
    box.appendChild(el('div', 'agent-label', 'Pending recommendations (' + items.length + ')'));
    if (!items.length) { box.appendChild(el('div', 'muted', 'Nothing waiting for approval.')); return box; }
    items.forEach(function (it) { box.appendChild(recEl(st, it)); });
    return box;
  }
  function renderPanel(st) {
    var box = st.container;
    box.textContent = '';
    box.classList.add('agent-panel');
    if (st.error) { box.appendChild(el('div', 'agent-error', st.error)); }
    var s = st.state;
    if (!s) {
      if (!st.error) { box.appendChild(el('div', 'muted', 'Loading agent panel...')); }
      return;
    }
    box.appendChild(headerEl(st, s));
    box.appendChild(policyEl(s.policy || {}));
    if (st.notice) { box.appendChild(noticeEl(st)); }
    if (s.injection && s.injection.detected) { box.appendChild(injectionEl(s.injection)); }
    box.appendChild(lastRunEl(st, s.last_run));
    box.appendChild(pendingEl(st, s.pending || []));
  }

  function runAgent(st) {
    st.busy = true;
    st.notice = null;
    st.prevRunId = st.state && st.state.last_run ? st.state.last_run.run_id : null;
    renderPanel(st);
    var url = '/api/agent-panel/' + encodeURIComponent(st.scope) + '/' + encodeURIComponent(st.targetId) + '/run';
    return request('POST', url).then(function (res) {
      st.busy = false;
      if (res.ok) {
        st.awaitUntil = Date.now() + AWAIT_RUN_MS;
        st.notice = { ok: true, text: 'Run started.' };
      } else {
        st.notice = { ok: false, text: 'Run refused (' + res.status + '): ' + reasonOf(res) };
      }
      return refresh(st);
    }).catch(function (e) {
      st.busy = false;
      st.notice = { ok: false, text: 'Run request failed: ' + e.message };
      return refresh(st);
    });
  }
  function decide(st, recId, verb) {
    st.busy = true;
    st.notice = null;
    renderPanel(st);
    var url = '/api/agent-panel/recommendations/' + encodeURIComponent(recId) + '/' + verb;
    var body = verb === 'reject' ? {} : undefined;
    return request('POST', url, body).then(function (res) {
      st.busy = false;
      var msg = res.data.message || recId;
      window.dispatchEvent(new Event('attention-refresh'));
      st.notice = res.ok ? { ok: true, text: (verb === 'approve' ? 'Approved: ' : 'Rejected: ') + msg }
        : { ok: false, text: verb + ' refused (' + res.status + '): ' + reasonOf(res) };
      return refresh(st);
    }).catch(function (e) {
      st.busy = false;
      st.notice = { ok: false, text: 'Request failed: ' + e.message };
      return refresh(st);
    });
  }

  function mount(container, scope, targetId) {
    if (!container) { return null; }
    if (container._agentPanel) { container._agentPanel.destroy(); }
    var st = { container: container, scope: scope, targetId: String(targetId), state: null, error: null,
      notice: null, busy: false, outputOpen: false, timer: null, dead: false, awaitUntil: 0, prevRunId: null };
    st.onVis = function () { if (!st.dead && !document.hidden) { refresh(st); } };
    document.addEventListener('visibilitychange', st.onVis);
    var handle = {
      refresh: function () { return refresh(st); },
      destroy: function () {
        st.dead = true;
        clearTimeout(st.timer);
        document.removeEventListener('visibilitychange', st.onVis);
        if (container._agentPanel === handle) { container._agentPanel = null; }
      }
    };
    container._agentPanel = handle;
    refresh(st);
    return handle;
  }

  function mountAll(root) {
    var nodes = (root || document).querySelectorAll('[data-agent-scope]');
    Array.prototype.forEach.call(nodes, function (n) {
      var target = n.getAttribute('data-agent-target');
      if (target) { mount(n, n.getAttribute('data-agent-scope'), target); }
    });
  }

  window.AgentPanel = { mount: mount, mountAll: mountAll };
})();
