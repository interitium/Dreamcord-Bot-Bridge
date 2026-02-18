(() => {
  const NS = 'dreamcord-sillytavern-bridge';
  const ST_PLUGIN_API = '/api/plugins/dreamcord-sillytavern-bridge';
  const STANDALONE_PORTS = [3710, 3711];

  let API = ST_PLUGIN_API;
  let rows = [];
  let searchTerm = '';
  let apiResolved = false;

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === 'class') node.className = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k === 'text') node.textContent = v;
      else node.setAttribute(k, v);
    });
    (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (c == null) return;
      if (typeof c === 'string') node.appendChild(document.createTextNode(c));
      else node.appendChild(c);
    });
    return node;
  }

  function getStHeaders() {
    try {
      if (typeof window.getRequestHeaders === 'function') {
        return window.getRequestHeaders() || {};
      }
    } catch (_) {}
    const headers = {};
    const meta = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (meta) headers['X-CSRF-Token'] = meta;
    return headers;
  }

  async function getFreshCsrfToken() {
    try {
      const res = await fetch('/csrf-token', { credentials: 'include' });
      if (!res.ok) return '';
      const data = await res.json().catch(() => ({}));
      return String(data?.token || '');
    } catch (_) {
      return '';
    }
  }

  async function jget(path) {
    await resolveApi();
    const isStPlugin = API === ST_PLUGIN_API;
    const csrf = isStPlugin ? await getFreshCsrfToken() : '';
    const res = await fetch(`${API}${path}`, {
      credentials: isStPlugin ? 'include' : 'omit',
      mode: isStPlugin ? 'same-origin' : 'cors',
      headers: isStPlugin ? { ...getStHeaders(), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } : { Accept: 'application/json' }
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
    return data;
  }

  async function jsend(path, method, body) {
    await resolveApi();
    const isStPlugin = API === ST_PLUGIN_API;
    const csrf = isStPlugin ? await getFreshCsrfToken() : '';
    const res = await fetch(`${API}${path}`, {
      method,
      credentials: isStPlugin ? 'include' : 'omit',
      mode: isStPlugin ? 'same-origin' : 'cors',
      headers: {
        'Content-Type': 'application/json',
        ...(isStPlugin ? { ...getStHeaders(), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } : { Accept: 'application/json' })
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
    return data;
  }

  function showStatus(msg, isErr = false) {
    const out = document.getElementById('dcst-status');
    if (!out) return;
    out.textContent = msg || '';
    out.style.color = isErr ? '#ff9ca8' : '#9dd4ff';
  }

  function readRowFields(sourceId) {
    const get = (id) => document.getElementById(`${id}-${sourceId}`)?.value || '';
    const getBool = (id) => Boolean(document.getElementById(`${id}-${sourceId}`)?.checked);
    return {
      name: get('dcst-name'),
      description: get('dcst-description'),
      bio: get('dcst-bio'),
      status_text: get('dcst-status-text'),
      avatar_url: get('dcst-avatar-url'),
      banner_url: get('dcst-banner-url'),
      room_id: get('dcst-room-id'),
      api_key: get('dcst-api-key'),
      bot_token: get('dcst-bot-token'),
      presence_enabled: getBool('dcst-presence-enabled'),
      responder_enabled: getBool('dcst-responder-enabled')
    };
  }

  function renderRows() {
    const host = document.getElementById('dcst-rows');
    if (!host) return;
    host.innerHTML = '';
    const q = String(searchTerm || '').trim().toLowerCase();
    const visibleRows = !q
      ? rows
      : rows.filter((row) => {
          const c = row.character || {};
          const haystack = [
            row.source_id,
            c.name,
            c.description,
            c.status_text,
            row.mapped_app_name
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          return haystack.includes(q);
        });

    if (!visibleRows.length) {
      host.appendChild(el('div', { class: 'dcst-empty', text: 'No characters found.' }));
      return;
    }

    visibleRows.forEach((row, idx) => {
      const sourceId = String(row.source_id || '');
      const c = row.character || {};
      const details = el('details', { class: 'dcst-item' });
      if (idx === 0) details.open = true;

      const summary = el('summary', { class: 'dcst-summary' }, [
        el('span', { class: 'dcst-title', text: c.name || sourceId || 'Character' }),
        el('div', { class: 'dcst-summary-pills' }, [
          el('span', {
            class: `dcst-pill ${row.mapped_active ? 'ok' : 'warn'}`,
            text: row.mapped_app_name ? `${row.mapped_app_name}${row.mapped_active ? '' : ' (inactive)'}` : 'Not mapped'
          }),
          el('span', {
            class: `dcst-pill ${(row.presence?.connected ? 'ok' : 'warn')}`,
            text: `Presence: ${row.presence?.status || 'offline'}`
          }),
          el('span', {
            class: `dcst-pill ${(row.responder?.enabled ? 'ok' : 'warn')}`,
            text: `Responder: ${row.responder?.enabled ? 'on' : 'off'}`
          })
        ])
      ]);

      const fields = el('div', { class: 'dcst-fields' }, [
        el('label', { text: 'Name' }),
        el('input', { id: `dcst-name-${sourceId}`, value: c.name || '', placeholder: 'Name' }),

        el('label', { text: 'Description' }),
        el('input', { id: `dcst-description-${sourceId}`, value: c.description || '', placeholder: 'Description' }),

        el('label', { text: 'Bio' }),
        el('textarea', { id: `dcst-bio-${sourceId}`, rows: '4', placeholder: 'Bio' }, c.bio || ''),

        el('label', { text: 'Status text' }),
        el('input', { id: `dcst-status-text-${sourceId}`, value: c.status_text || '', placeholder: 'Status text' }),

        el('label', { text: 'Avatar URL' }),
        el('input', { id: `dcst-avatar-url-${sourceId}`, value: c.avatar_url || '', placeholder: 'https://...' }),

        el('label', { text: 'Banner URL' }),
        el('input', { id: `dcst-banner-url-${sourceId}`, value: c.banner_url || '', placeholder: 'https://...' }),

        el('label', { text: 'Room ID' }),
        el('input', { id: `dcst-room-id-${sourceId}`, value: c.room_id || '', placeholder: 'Room ID' }),

        el('label', { text: 'Character API key' }),
        el('input', { id: `dcst-api-key-${sourceId}`, value: c.api_key || '', placeholder: 'Nomi/API key for this character' }),

        el('label', { text: 'Dreamcord bot token' }),
        el('input', { id: `dcst-bot-token-${sourceId}`, value: c.bot_token || '', placeholder: 'dcb_...' }),

        el('label', { text: 'Bot presence enabled' }),
        el('input', { id: `dcst-presence-enabled-${sourceId}`, type: 'checkbox' }),

        el('label', { text: 'Auto respond enabled' }),
        el('input', { id: `dcst-responder-enabled-${sourceId}`, type: 'checkbox' })
      ]);
      const enabledCb = fields.querySelector(`#dcst-presence-enabled-${sourceId}`);
      if (enabledCb) enabledCb.checked = Boolean(row.override?.presence_enabled === true);
      const responderCb = fields.querySelector(`#dcst-responder-enabled-${sourceId}`);
      if (responderCb) responderCb.checked = Boolean(row.override?.responder_enabled === true);
      if (enabledCb) {
        enabledCb.addEventListener('change', async () => {
          showStatus(`Saving ${c.name || sourceId}...`);
          try {
            await jsend(`/characters/${encodeURIComponent(sourceId)}/override`, 'PUT', readRowFields(sourceId));
            await loadPreview();
            showStatus(`Saved override for ${c.name || sourceId}.`);
          } catch (err) {
            showStatus(`Save failed: ${err.message || err}`, true);
          }
        });
      }
      if (responderCb) {
        responderCb.addEventListener('change', async () => {
          showStatus(`Saving ${c.name || sourceId}...`);
          try {
            await jsend(`/characters/${encodeURIComponent(sourceId)}/override`, 'PUT', readRowFields(sourceId));
            await loadPreview();
            showStatus(`Saved override for ${c.name || sourceId}.`);
          } catch (err) {
            showStatus(`Save failed: ${err.message || err}`, true);
          }
        });
      }

      const actions = el('div', { class: 'dcst-actions' }, [
        el('button', { type: 'button', text: 'Connect bot' }),
        el('button', { type: 'button', text: 'Disconnect bot' }),
        el('button', { type: 'button', text: 'Save override' }),
        el('button', { type: 'button', text: 'Clear override' })
      ]);

      actions.children[0].onclick = async () => {
        showStatus(`Connecting ${c.name || sourceId}...`);
        try {
          const body = readRowFields(sourceId);
          await jsend(`/characters/${encodeURIComponent(sourceId)}/presence/connect`, 'POST', {
            bot_token: body.bot_token || '',
            presence_enabled: true
          });
          await loadPreview();
          showStatus(`Connected ${c.name || sourceId}.`);
        } catch (err) {
          showStatus(`Connect failed: ${err.message || err}`, true);
        }
      };

      actions.children[1].onclick = async () => {
        showStatus(`Disconnecting ${c.name || sourceId}...`);
        try {
          await jsend(`/characters/${encodeURIComponent(sourceId)}/presence/disconnect`, 'POST', {});
          await loadPreview();
          showStatus(`Disconnected ${c.name || sourceId}.`);
        } catch (err) {
          showStatus(`Disconnect failed: ${err.message || err}`, true);
        }
      };

      actions.children[2].onclick = async () => {
        showStatus(`Saving ${c.name || sourceId}...`);
        try {
          await jsend(`/characters/${encodeURIComponent(sourceId)}/override`, 'PUT', readRowFields(sourceId));
          await loadPreview();
          showStatus(`Saved override for ${c.name || sourceId}.`);
        } catch (err) {
          showStatus(`Save failed: ${err.message || err}`, true);
        }
      };

      actions.children[3].onclick = async () => {
        showStatus(`Clearing override for ${c.name || sourceId}...`);
        try {
          await jsend(`/characters/${encodeURIComponent(sourceId)}/override`, 'DELETE');
          await loadPreview();
          showStatus(`Cleared override for ${c.name || sourceId}.`);
        } catch (err) {
          showStatus(`Clear failed: ${err.message || err}`, true);
        }
      };

      details.appendChild(summary);
      details.appendChild(fields);
      details.appendChild(actions);
      host.appendChild(details);
    });
  }

  async function loadPreview() {
    showStatus('Loading character preview...');
    try {
      const data = await jget('/characters/preview');
      rows = Array.isArray(data.rows) ? data.rows : [];
      renderRows();
      showStatus(`Loaded ${rows.length} characters.`);
    } catch (err) {
      showStatus(`Preview failed: ${err.message || err}`, true);
    }
  }

  async function syncNow(dryRun) {
    showStatus(dryRun ? 'Running dry sync...' : 'Running sync...');
    try {
      const data = await jsend('/sync/characters', 'POST', { dry_run: !!dryRun });
      showStatus(`Sync done: created=${data.created?.length || 0}, updated=${data.updated?.length || 0}, unchanged=${data.unchanged?.length || 0}`);
      await loadPreview();
    } catch (err) {
      showStatus(`Sync failed: ${err.message || err}`, true);
    }
  }

  function mountUi() {
    if (document.getElementById('dcst-panel')) return;

    const style = el('style', {
      id: 'dcst-style',
      html: `
      #dcst-panel { border:1px solid #3a4356; border-radius:10px; padding:10px; margin-top:10px; background:#151a24; }
      #dcst-panel h3 { margin:0 0 8px; font-size:14px; color:#dce6ff; }
      .dcst-top { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px; }
      .dcst-top input { min-width:260px; border:1px solid #43506a; background:#101521; color:#e2eaff; border-radius:7px; padding:6px 10px; }
      .dcst-top button { border:1px solid #43506a; background:#222c3f; color:#e2eaff; border-radius:7px; padding:6px 10px; cursor:pointer; }
      #dcst-rows { display:grid; gap:8px; }
      .dcst-item { border:1px solid #33405a; border-radius:9px; background:#121826; overflow:hidden; }
      .dcst-summary { cursor:pointer; list-style:none; padding:8px 10px; display:flex; align-items:center; justify-content:space-between; gap:8px; background:#1c2436; }
      .dcst-summary-pills { display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
      .dcst-summary::-webkit-details-marker { display:none; }
      .dcst-title { color:#eaf0ff; font-weight:600; }
      .dcst-pill { font-size:11px; border-radius:999px; padding:2px 8px; border:1px solid #4a5978; color:#cfdbf6; }
      .dcst-pill.ok { border-color:#356c55; color:#9ff0c3; }
      .dcst-pill.warn { border-color:#7b6142; color:#ffd39b; }
      .dcst-fields { display:grid; grid-template-columns: 160px 1fr; gap:6px 8px; padding:10px; }
      .dcst-fields label { color:#a6b8dd; font-size:12px; align-self:center; }
      .dcst-fields input, .dcst-fields textarea { width:100%; border:1px solid #3a4250; background:#101521; color:#e7ecff; border-radius:7px; padding:6px 8px; }
      .dcst-actions { display:flex; gap:6px; padding:0 10px 10px; }
      .dcst-actions button { border:1px solid #43506a; background:#222c3f; color:#e2eaff; border-radius:7px; padding:6px 10px; cursor:pointer; }
      .dcst-empty { color:#9fb0d5; font-size:12px; padding:6px 2px; }
      #dcst-status { font-size:12px; color:#9dd4ff; margin-top:8px; }
      @media (max-width: 900px) { .dcst-fields { grid-template-columns: 1fr; } }
    `
    });

    const panel = el('div', { id: 'dcst-panel' }, [
      el('h3', { text: 'Dreamcord SillyTavern Bridge' }),
      el('div', { class: 'dcst-top' }, [
        el('input', { id: 'dcst-search', type: 'text', placeholder: 'Search characters...' }),
        el('button', { id: 'dcst-refresh', type: 'button', text: 'Refresh preview' }),
        el('button', { id: 'dcst-sync-dry', type: 'button', text: 'Dry sync' }),
        el('button', { id: 'dcst-sync', type: 'button', text: 'Sync now' })
      ]),
      el('div', { id: 'dcst-rows' }),
      el('div', { id: 'dcst-status' })
    ]);

    const host = document.getElementById('extensions_settings') || document.getElementById('extensions_settings2') || document.body;
    if (!document.getElementById('dcst-style')) document.head.appendChild(style);
    host.appendChild(panel);

    document.getElementById('dcst-refresh').onclick = () => loadPreview();
    document.getElementById('dcst-sync-dry').onclick = () => syncNow(true);
    document.getElementById('dcst-sync').onclick = () => syncNow(false);
    const searchInput = document.getElementById('dcst-search');
    if (searchInput) {
      searchInput.addEventListener('input', () => {
        searchTerm = String(searchInput.value || '');
        renderRows();
      });
    }

    loadPreview();
  }

  async function resolveApi() {
    if (apiResolved) return;
    // Try the ST plugin path first
    try {
      const res = await fetch(`${ST_PLUGIN_API}/health`, {
        credentials: 'include',
        headers: getStHeaders()
      });
      if (res.ok) {
        API = ST_PLUGIN_API;
        apiResolved = true;
        console.log(`[${NS}] using ST plugin API`);
        return;
      }
    } catch (_) {}
    // Probe standalone bridge on common ports
    const origin = window.location.origin.replace(/:\d+$/, '');
    for (const port of STANDALONE_PORTS) {
      try {
        const base = `${origin}:${port}`;
        const res = await fetch(`${base}/health`, { mode: 'cors' });
        if (res.ok) {
          API = base;
          apiResolved = true;
          console.log(`[${NS}] using standalone bridge at ${base}`);
          return;
        }
      } catch (_) {}
    }
    console.warn(`[${NS}] no bridge API found — ST plugin 404 and standalone not reachable`);
  }

  function start() {
    mountUi();
    const observer = new MutationObserver(() => {
      if (!document.getElementById('dcst-panel')) mountUi();
    });
    observer.observe(document.body, { childList: true, subtree: true });
    console.log(`[${NS}] settings panel mounted`);
    resolveApi();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
})();
