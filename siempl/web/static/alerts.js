/* alerts list page: inline status/severity edits, bulk actions, preview drawer. All data goes in via textContent. */
(function () {
  'use strict';
  var STATUS_LABELS = {new: 'New', active: 'Active', closed_tp: 'Closed - True Positive', closed_fp: 'Closed - False Positive'};
  var SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];

  function flash(msg, isError) {
    var el = document.getElementById('alerts-flash');
    if (!el) { return; }
    el.textContent = msg;
    el.hidden = !msg;
    el.className = 'alerts-flash' + (isError ? ' alerts-flash-error' : '');
  }

  function post(url, body) {
    return fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
      .then(function (r) {
        return r.json().then(function (d) {
          if (!r.ok) { throw new Error(d.error || ('HTTP ' + r.status)); }
          return d;
        });
      });
  }

  function setField(alertId, field, value) {
    return post('/api/alerts/' + encodeURIComponent(alertId) + '/' + field, (function () {
      var b = {}; b[field] = value; return b;
    })());
  }

  function refreshCharts() {
    var rule = new URLSearchParams(window.location.search).get('rule') || '';
    return fetch('/alerts/fragments/charts?rule=' + encodeURIComponent(rule)).then(function (r) { return r.text(); }).then(function (html) {
      var cur = document.getElementById('alert-charts');
      if (!cur) { return; }
      var tmp = document.createElement('div');
      tmp.innerHTML = html;
      var fresh = tmp.querySelector('#alert-charts');
      if (fresh) { cur.replaceWith(fresh); }
    });
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }

  window.AlertsUI = {flash: flash, post: post, setField: setField, refreshCharts: refreshCharts, el: el,
                     STATUS_LABELS: STATUS_LABELS, SEVERITIES: SEVERITIES};
})();
