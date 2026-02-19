(() => {
  const NS = 'dreamcord-bot-bridge';
  const ST_PLUGIN_APIS = ['/api/plugins/dreamcord-bot-bridge', '/api/plugins/dreamcord-sillytavern-bridge'];
  const STANDALONE_PORTS = [3710, 3711];
  const PANEL_COLLAPSED_KEY = 'dcst.panelCollapsed.v1';

  let API = ST_PLUGIN_APIS[0];
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
    const isStPlugin = ST_PLUGIN_APIS.includes(API);
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
    const isStPlugin = ST_PLUGIN_APIS.includes(API);
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

  function readPanelCollapsed() {
    try {
      return localStorage.getItem(PANEL_COLLAPSED_KEY) === '1';
    } catch (_) {
      return false;
    }
  }

  function writePanelCollapsed(collapsed) {
    try {
      localStorage.setItem(PANEL_COLLAPSED_KEY, collapsed ? '1' : '0');
    } catch (_) {}
  }

  function parseRoomIdsInput(value) {
    const parts = String(value || '')
      .split(/[\n,]+/)
      .map((v) => String(v || '').trim())
      .filter(Boolean);
    return Array.from(new Set(parts)).slice(0, 64);
  }

  function readRowFields(sourceId) {
    const get = (id) => document.getElementById(`${id}-${sourceId}`)?.value || '';
    const getBool = (id) => Boolean(document.getElementById(`${id}-${sourceId}`)?.checked);
    const parseIntSafe = (value, fallback) => {
      const n = Number.parseInt(String(value || '').trim(), 10);
      if (!Number.isFinite(n)) return fallback;
      return n;
    };
    const roomIds = parseRoomIdsInput(get('dcst-room-id'));
    const memoryMessages = Math.max(0, Math.min(20, parseIntSafe(get('dcst-memory-messages'), 6)));
    return {
      name: get('dcst-name'),
      description: get('dcst-description'),
      bio: get('dcst-bio'),
      character_prefix: get('dcst-character-prefix'),
      status_text: get('dcst-status-text'),
      room_ids: roomIds,
      room_id: roomIds[0] || '',
      bot_token: get('dcst-bot-token'),
      presence_enabled: getBool('dcst-presence-enabled'),
      responder_enabled: getBool('dcst-responder-enabled'),
      respond_any_message: getBool('dcst-respond-any-message'),
      trigger_keyword: get('dcst-trigger-keyword'),
      memory_enabled: getBool('dcst-memory-enabled'),
      memory_messages: memoryMessages
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
      const roomIdsRaw = row?.override?.room_ids;
      const roomValue = Array.isArray(roomIdsRaw)
        ? roomIdsRaw.join(', ')
        : String(roomIdsRaw || row?.override?.room_id || c.room_id || '');
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
          }),
          el('span', {
            class: `dcst-pill ${(row.override?.respond_any_message ? 'ok' : 'warn')}`,
            text: `All msgs: ${row.override?.respond_any_message ? 'on' : 'off'}`
          }),
          el('span', {
            class: `dcst-pill ${row.override?.memory_enabled === false ? 'warn' : 'ok'}`,
            text: `Context: ${row.override?.memory_enabled === false ? 'off' : 'on'}`
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

        el('label', { text: 'Character-specific prompt prefix (image generation)' }),
        el('textarea', { id: `dcst-character-prefix-${sourceId}`, rows: '3', placeholder: 'Used when generating images from Dreamcord.' }, row.override?.character_prefix || c.character_prefix || ''),

        el('label', { text: 'Status text' }),
        el('input', { id: `dcst-status-text-${sourceId}`, value: c.status_text || '', placeholder: 'Status text' }),

        el('label', { text: 'Restricted room IDs' }),
        el('input', { id: `dcst-room-id-${sourceId}`, value: roomValue, placeholder: 'room1, room2 (Dreamcord channel IDs)' }),

        el('label', { text: 'Dreamcord bot token' }),
        el('input', { id: `dcst-bot-token-${sourceId}`, value: c.bot_token || '', placeholder: 'dcb_...' }),

        el('label', { text: 'Bot presence enabled' }),
        el('input', { id: `dcst-presence-enabled-${sourceId}`, type: 'checkbox' }),

        el('label', { text: 'Auto respond enabled' }),
        el('input', { id: `dcst-responder-enabled-${sourceId}`, type: 'checkbox' }),

        el('label', { text: 'Respond to all messages in allowed rooms' }),
        el('input', { id: `dcst-respond-any-message-${sourceId}`, type: 'checkbox' }),

        el('label', { text: 'Trigger keyword (optional)' }),
        el('input', { id: `dcst-trigger-keyword-${sourceId}`, value: row.override?.trigger_keyword || '', placeholder: 'supergirl' }),

        el('label', { text: 'Inject recent room context' }),
        el('input', { id: `dcst-memory-enabled-${sourceId}`, type: 'checkbox' }),

        el('label', { text: 'Context messages (0-20)' }),
        el('input', { id: `dcst-memory-messages-${sourceId}`, type: 'number', min: '0', max: '20', step: '1', value: String(row.override?.memory_messages ?? 6) })
      ]);
      const enabledCb = fields.querySelector(`#dcst-presence-enabled-${sourceId}`);
      if (enabledCb) enabledCb.checked = Boolean(row.override?.presence_enabled === true);
      const responderCb = fields.querySelector(`#dcst-responder-enabled-${sourceId}`);
      if (responderCb) responderCb.checked = Boolean(row.override?.responder_enabled === true);
      const respondAnyCb = fields.querySelector(`#dcst-respond-any-message-${sourceId}`);
      if (respondAnyCb) respondAnyCb.checked = Boolean(row.override?.respond_any_message === true);
      const memoryEnabledCb = fields.querySelector(`#dcst-memory-enabled-${sourceId}`);
      if (memoryEnabledCb) memoryEnabledCb.checked = row.override?.memory_enabled !== false;
      const memoryMessagesInput = fields.querySelector(`#dcst-memory-messages-${sourceId}`);
      if (memoryMessagesInput) memoryMessagesInput.value = String(row.override?.memory_messages ?? 6);
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
      if (respondAnyCb) {
        respondAnyCb.addEventListener('change', async () => {
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
      if (memoryEnabledCb) {
        memoryEnabledCb.addEventListener('change', async () => {
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
      if (memoryMessagesInput) {
        memoryMessagesInput.addEventListener('change', async () => {
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
      #dcst-panel { border:1px solid #46516a; border-radius:10px; margin-top:10px; background:#151a24; overflow:hidden; box-shadow:0 8px 22px rgba(0,0,0,.22); }
      #dcst-panel .inline-drawer-header { padding:10px 12px; border-bottom:1px solid #2b3447; display:flex; align-items:center; justify-content:space-between; gap:10px; cursor:pointer; background:linear-gradient(92deg, #16b86a 0%, #209d6e 35%, #b84655 70%, #dc4f5f 100%); }
      #dcst-panel .inline-drawer-header b { color:#f6fbff; font-size:14px; letter-spacing:.2px; text-shadow:0 1px 1px rgba(0,0,0,.35); }
      #dcst-panel .inline-drawer-icon { color:#f6fbff; cursor:pointer; }
      #dcst-panel .inline-drawer-icon:hover { color:#ffffff; filter:drop-shadow(0 0 4px rgba(255,255,255,.5)); }
      #dcst-body { padding:10px; }
      #dcst-panel.dcst-collapsed #dcst-body { display:none !important; }
      #dcst-panel.dcst-collapsed .inline-drawer-header { border-bottom:none; }
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
      .dcst-fields input:not([type="checkbox"]), .dcst-fields textarea { width:100%; border:1px solid #3a4250; background:#101521; color:#e7ecff; border-radius:7px; padding:6px 8px; }
      .dcst-fields input[type="checkbox"] {
        appearance:none; -webkit-appearance:none;
        width:46px; height:24px; padding:0;
        border-radius:999px;
        border:1px solid #8a3b45;
        background:#5f2930;
        position:relative;
        cursor:pointer;
        justify-self:start;
        transition:background-color .15s ease, border-color .15s ease;
      }
      .dcst-fields input[type="checkbox"]::before {
        content:'';
        position:absolute;
        top:2px; left:2px;
        width:18px; height:18px;
        border-radius:50%;
        background:#ffd7dc;
        box-shadow:0 1px 2px rgba(0,0,0,.35);
        transition:transform .15s ease, background-color .15s ease;
      }
      .dcst-fields input[type="checkbox"]:checked {
        background:#1d6a43;
        border-color:#2e9f64;
      }
      .dcst-fields input[type="checkbox"]:checked::before {
        transform:translateX(22px);
        background:#d8ffe9;
      }
      .dcst-fields input[type="checkbox"]:focus-visible {
        outline:2px solid #74a7ff;
        outline-offset:2px;
      }
      .dcst-actions { display:flex; gap:6px; padding:0 10px 10px; }
      .dcst-actions button { border:1px solid #43506a; background:#222c3f; color:#e2eaff; border-radius:7px; padding:6px 10px; cursor:pointer; }
      .dcst-empty { color:#9fb0d5; font-size:12px; padding:6px 2px; }
      #dcst-status { font-size:12px; color:#9dd4ff; margin-top:8px; }
      @media (max-width: 900px) { .dcst-fields { grid-template-columns: 1fr; } }
    `
    });

    const collapsed = readPanelCollapsed();
    const title = el('b', {
      'data-i18n': 'Dreamcord Bot Bridge',
      text: 'Dreamcord Bot Bridge'
    });
    const toggle = el('div', {
      class: `inline-drawer-icon fa-solid interactable ${collapsed ? 'down fa-circle-chevron-down' : 'up fa-circle-chevron-up'}`,
      tabindex: '0',
      role: 'button',
      title: collapsed ? 'Expand' : 'Collapse',
      'aria-label': collapsed ? 'Expand Dreamcord Bot Bridge panel' : 'Collapse Dreamcord Bot Bridge panel'
    });
    const head = el('div', { class: 'inline-drawer-toggle inline-drawer-header' }, [
      title,
      toggle
    ]);

    const body = el('div', { id: 'dcst-body', class: 'inline-drawer-content' }, [
      el('div', { class: 'dcst-top' }, [
        el('input', { id: 'dcst-search', type: 'text', placeholder: 'Search characters...' }),
        el('button', { id: 'dcst-refresh', type: 'button', text: 'Refresh preview' }),
        el('button', { id: 'dcst-sync-dry', type: 'button', text: 'Dry sync' }),
        el('button', { id: 'dcst-sync', type: 'button', text: 'Sync now' })
      ]),
      el('div', { id: 'dcst-rows' }),
      el('div', { id: 'dcst-status' })
    ]);

    const panel = el('div', { id: 'dcst-panel', class: 'inline-drawer' }, [
      head,
      body
    ]);

    function applyCollapsed(next) {
      const isCollapsed = !!next;
      panel.classList.toggle('collapsed', isCollapsed);
      panel.classList.toggle('dcst-collapsed', isCollapsed);
      body.style.display = isCollapsed ? 'none' : 'block';
      body.toggleAttribute('hidden', isCollapsed);
      body.setAttribute('aria-hidden', isCollapsed ? 'true' : 'false');
      toggle.classList.remove('up', 'down', 'fa-circle-chevron-up', 'fa-circle-chevron-down');
      toggle.classList.add(isCollapsed ? 'down' : 'up', isCollapsed ? 'fa-circle-chevron-down' : 'fa-circle-chevron-up');
      toggle.title = isCollapsed ? 'Expand' : 'Collapse';
      toggle.setAttribute('aria-label', isCollapsed ? 'Expand Dreamcord Bot Bridge panel' : 'Collapse Dreamcord Bot Bridge panel');
      writePanelCollapsed(isCollapsed);
    }

    const onToggle = () => {
      const shouldCollapse = body.style.display !== 'none';
      applyCollapsed(shouldCollapse);
      if (!shouldCollapse && !rows.length) {
        loadPreview();
      }
    };
    head.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      onToggle();
    });
    head.addEventListener('pointerdown', (ev) => {
      if (ev.button !== 0) return;
      ev.preventDefault();
    });
    head.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter' && ev.key !== ' ') return;
      ev.preventDefault();
      onToggle();
    });
    head.setAttribute('tabindex', '0');
    head.setAttribute('role', 'button');
    head.setAttribute('aria-label', 'Toggle Dreamcord Bot Bridge panel');
    toggle.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      onToggle();
    });
    toggle.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter' && ev.key !== ' ') return;
      ev.preventDefault();
      onToggle();
    });
    applyCollapsed(collapsed);

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

    if (!collapsed) loadPreview();
  }

  async function resolveApi() {
    if (apiResolved) return;
    // Try the ST plugin path first
    for (const pluginApi of ST_PLUGIN_APIS) {
      try {
        const res = await fetch(`${pluginApi}/health`, {
          credentials: 'include',
          headers: getStHeaders()
        });
        if (res.ok) {
          API = pluginApi;
          apiResolved = true;
          console.log(`[${NS}] using ST plugin API ${pluginApi}`);
          return;
        }
      } catch (_) {}
    }
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
    console.warn(`[${NS}] no bridge API found — ST plugin and standalone not reachable`);
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
