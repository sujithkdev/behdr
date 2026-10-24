'use strict';
const $ = (id) => document.getElementById(id);
let csrf = '';
let timer;
async function api(path, options = {}) {
  const response = await fetch(path, {credentials: 'same-origin', ...options,
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf, ...options.headers}});
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) showLogin();
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}
function error(message) { $('message').textContent = message; }
function showLogin() { clearTimeout(timer); $('login').hidden = false; $('workspace').hidden = true; }
function table(id, rows, keys, onClick) {
  const target = $(id); target.replaceChildren();
  for (const row of rows) {
    const tr = document.createElement('tr');
    for (const key of keys) { const td = document.createElement('td'); td.textContent = row[key] ?? '—'; tr.append(td); }
    if (onClick) {
      const td = document.createElement('td'); const button = document.createElement('button');
      button.textContent = 'Evidence'; button.addEventListener('click', () => onClick(row));
      td.append(button); tr.append(td);
    }
    target.append(tr);
  }
  if (!rows.length) {
    const tr = document.createElement('tr'); const td = document.createElement('td');
    td.colSpan = keys.length + Number(Boolean(onClick)); td.textContent = 'No records yet'; tr.append(td); target.append(tr);
  }
}
async function refresh() {
  clearTimeout(timer);
  try {
    const data = await api('/api/status');
    $('events-count').textContent = data.stats.total_events;
    $('alerts-count').textContent = data.stats.total_alerts;
    $('online-count').textContent = data.systems.filter(s => s.status === 'online').length;
    $('backlog').textContent = `${data.backlog.pending || 0} pending · ${data.backlog.failed || 0} failed`;
    table('systems', data.systems, ['system_id', 'hostname', 'status', 'agent_ver']);
    table('alerts', data.alerts, ['risk_level', 'system_id', 'process', 'reason'], async row => {
      try { $('evidence').textContent = JSON.stringify(await api(`/api/alerts/${row.id}`), null, 2); }
      catch (e) { error(e.message); }
    });
    $('updated').textContent = `Updated ${new Date().toLocaleTimeString()}`; error('');
  } catch (e) { error(e.message); }
  if (!$('workspace').hidden) timer = setTimeout(refresh, 10000);
}
async function signedIn(user) {
  csrf = user.csrf; $('identity').textContent = `${user.username} · ${user.role}`;
  $('login').hidden = true; $('workspace').hidden = false;
  $('enrollment').hidden = user.role !== 'admin'; $('command-panel').hidden = user.role === 'viewer'; await refresh();
}
$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  try { await signedIn(await api('/auth/login', {method: 'POST', body: JSON.stringify({username: $('username').value, password: $('password').value})})); $('password').value = ''; }
  catch (e) { error(e.message); }
});
$('logout').addEventListener('click', async () => {
  try { await api('/auth/logout', {method: 'POST', body: '{}'}); csrf = ''; showLogin(); } catch (e) { error(e.message); }
});
$('refresh').addEventListener('click', refresh);
$('enroll-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const data = await api('/api/agents/enroll', {method: 'POST', body: JSON.stringify({system_id: $('system-id').value})});
    $('enrolled').textContent = `Save this credential securely. It is shown once.\nEDR_SYSTEM_ID=${data.system_id}\nEDR_API_KEY=${data.token}`;
  } catch (e) { error(e.message); }
});
$('command-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const result = await api('/api/command', {method: 'POST', body: JSON.stringify({system_id: $('command-system').value, action: $('action').value, params: {}})});
    $('command-result').textContent = `Command ${result.id} queued. Select “Load results” after the agent polls.`;
  } catch (e) { error(e.message); }
});
$('load-results').addEventListener('click', async () => {
  try { $('command-result').textContent = JSON.stringify(await api(`/api/commands?system_id=${encodeURIComponent($('command-system').value)}`), null, 2); } catch (e) { error(e.message); }
});
api('/auth/me').then(signedIn).catch(showLogin);
