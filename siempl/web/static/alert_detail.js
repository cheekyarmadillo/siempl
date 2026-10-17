// Alert detail page: status, severity and owner changes, and the comment form.
// Every write goes through the JSON API under /api/alerts/<id>/. Dynamic text uses textContent only.
(function () {
  'use strict';

  var root = document.getElementById('alert-root');
  if (!root) {
    return;
  }
  var base = '/api/alerts/' + encodeURIComponent(root.getAttribute('data-alert-id') || '');

  function setMessage(id, text, isError) {
    var el = document.getElementById(id);
    if (!el) {
      return;
    }
    el.textContent = text;
    el.style.color = isError ? 'var(--color-red)' : '';
  }

  function post(path, payload) {
    return fetch(base + path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(function (resp) {
      return resp.json().catch(function () {
        return {};
      }).then(function (data) {
        return {ok: resp.ok, data: data};
      });
    });
  }

  function errorText(result) {
    return (result.data && result.data.error) || 'Request failed';
  }

  function saveThen(msgId, path, payload) {
    setMessage(msgId, 'Saving…', false);
    post(path, payload).then(function (result) {
      if (result.ok) {
        location.reload();
      } else {
        setMessage(msgId, errorText(result), true);
      }
    }).catch(function (err) {
      setMessage(msgId, 'Error: ' + err.message, true);
    });
  }

  function bindSelect(id, path, key) {
    var el = document.getElementById(id);
    if (!el) {
      return;
    }
    el.addEventListener('change', function () {
      var payload = {};
      payload[key] = el.value;
      saveThen('alert-status-msg', path, payload);
    });
  }

  bindSelect('status-select', '/status', 'status');
  bindSelect('severity-select', '/severity', 'severity');

  var ownerBtn = document.getElementById('owner-save');
  var ownerInput = document.getElementById('owner-input');
  if (ownerBtn && ownerInput) {
    ownerBtn.addEventListener('click', function () {
      saveThen('alert-status-msg', '/owner', {owner: ownerInput.value.trim()});
    });
  }

  var form = document.getElementById('comment-form');
  if (form) {
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var text = (document.getElementById('comment-body').value || '').trim();
      if (!text) {
        setMessage('comment-msg', 'Write a comment first.', true);
        return;
      }
      setMessage('comment-msg', 'Posting…', false);
      post('/comment', {body: text}).then(function (result) {
        if (result.ok) {
          location.reload();
        } else {
          setMessage('comment-msg', errorText(result), true);
        }
      }).catch(function (err) {
        setMessage('comment-msg', 'Error: ' + err.message, true);
      });
    });
  }
})();
