const fs = require('node:fs/promises');
const path = require('node:path');

const DATA_DIR = path.join(__dirname, 'data');
const MAP_PATH = path.join(DATA_DIR, 'character-map.json');
const OVERRIDES_PATH = path.join(DATA_DIR, 'character-overrides.json');

const DREAMCORD_BASE_URL = String(process.env.DREAMCORD_BASE_URL || '').replace(/\/$/, '');
const DREAMCORD_BOT_TOKEN = String(process.env.DREAMCORD_BOT_TOKEN || '');
const DREAMCORD_ADMIN_USERNAME = String(process.env.DREAMCORD_ADMIN_USERNAME || '').trim();
const DREAMCORD_ADMIN_PASSWORD = String(process.env.DREAMCORD_ADMIN_PASSWORD || '');
const DREAMCORD_ADMIN_2FA = String(process.env.DREAMCORD_ADMIN_2FA || '').trim();
const SILLYTAVERN_BASE_URL = String(process.env.SILLYTAVERN_BASE_URL || '').replace(/\/$/, '');
const SILLYTAVERN_API_KEY = String(process.env.SILLYTAVERN_API_KEY || '').trim();
const SILLYTAVERN_CHARACTERS_URL = String(process.env.SILLYTAVERN_CHARACTERS_URL || '').trim();
const DEFAULT_TARGET_CHANNEL_ID = String(process.env.DEFAULT_TARGET_CHANNEL_ID || '').trim();
const DEFAULT_SOURCE_LABEL = String(process.env.DEFAULT_SOURCE_TAG || 'sillytavern').trim().slice(0, 40) || 'sillytavern';

let adminSessionCookie = '';

function hasBridgeConfig() {
  return !!(DREAMCORD_BASE_URL && SILLYTAVERN_BASE_URL && SILLYTAVERN_API_KEY && DREAMCORD_ADMIN_USERNAME && DREAMCORD_ADMIN_PASSWORD);
}

function isHttpUrl(value) {
  return /^https?:\/\//i.test(String(value || '').trim());
}

function slugify(input) {
  return String(input || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
    .slice(0, 80);
}

function extractCookieFromResponse(res, cookieName) {
  const fromGetSetCookie = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
  const fallback = res.headers.get('set-cookie');
  const all = [...fromGetSetCookie, ...(fallback ? [fallback] : [])].filter(Boolean);
  for (const raw of all) {
    const firstPart = String(raw).split(';')[0] || '';
    if (firstPart.toLowerCase().startsWith(`${String(cookieName).toLowerCase()}=`)) {
      return firstPart.trim();
    }
  }
  return '';
}

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function loadCharacterMap() {
  await ensureDataDir();
  try {
    const raw = await fs.readFile(MAP_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    return {};
  }
}

async function saveCharacterMap(map) {
  await ensureDataDir();
  await fs.writeFile(MAP_PATH, JSON.stringify(map || {}, null, 2), 'utf8');
}

async function loadCharacterOverrides() {
  await ensureDataDir();
  try {
    const raw = await fs.readFile(OVERRIDES_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    return {};
  }
}

async function saveCharacterOverrides(overrides) {
  await ensureDataDir();
  await fs.writeFile(OVERRIDES_PATH, JSON.stringify(overrides || {}, null, 2), 'utf8');
}

function sanitizeCharacterOverride(input) {
  const next = {};
  const src = input && typeof input === 'object' ? input : {};
  if (src.name !== undefined) next.name = String(src.name || '').trim().slice(0, 80);
  if (src.description !== undefined) next.description = String(src.description || '').trim().slice(0, 2000);
  if (src.bio !== undefined) next.bio = String(src.bio || '').trim().slice(0, 4000);
  if (src.status_text !== undefined) next.status_text = String(src.status_text || '').trim().slice(0, 120);
  if (src.avatar_url !== undefined) next.avatar_url = isHttpUrl(src.avatar_url) ? String(src.avatar_url).trim() : '';
  if (src.banner_url !== undefined) next.banner_url = isHttpUrl(src.banner_url) ? String(src.banner_url).trim() : '';
  if (src.room_id !== undefined) next.room_id = String(src.room_id || '').trim().slice(0, 120);
  if (src.api_key !== undefined) next.api_key = String(src.api_key || '').trim().slice(0, 512);
  if (src.bot_token !== undefined) next.bot_token = String(src.bot_token || '').trim().slice(0, 512);
  return next;
}

function applyCharacterOverride(character, override) {
  if (!override || typeof override !== 'object') return character;
  return {
    ...character,
    name: override.name !== undefined && override.name !== '' ? String(override.name).trim().slice(0, 80) : character.name,
    description: override.description !== undefined ? String(override.description || '').trim().slice(0, 2000) : character.description,
    bio: override.bio !== undefined ? String(override.bio || '').trim().slice(0, 4000) : character.bio,
    status_text: override.status_text !== undefined ? String(override.status_text || '').trim().slice(0, 120) : character.status_text,
    avatar_url: override.avatar_url !== undefined ? (isHttpUrl(override.avatar_url) ? String(override.avatar_url).trim() : '') : character.avatar_url,
    banner_url: override.banner_url !== undefined ? (isHttpUrl(override.banner_url) ? String(override.banner_url).trim() : '') : character.banner_url,
    room_id: override.room_id !== undefined ? String(override.room_id || '').trim().slice(0, 120) : character.room_id,
    api_key: override.api_key !== undefined ? String(override.api_key || '').trim().slice(0, 512) : (character.api_key || ''),
    bot_token: override.bot_token !== undefined ? String(override.bot_token || '').trim().slice(0, 512) : (character.bot_token || '')
  };
}

async function stRequest(pathOrUrl, options = {}) {
  const isAbsolute = isHttpUrl(pathOrUrl);
  const url = isAbsolute ? String(pathOrUrl) : `${SILLYTAVERN_BASE_URL}${pathOrUrl.startsWith('/') ? '' : '/'}${pathOrUrl}`;
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'x-api-key': SILLYTAVERN_API_KEY,
    Authorization: `Bearer ${SILLYTAVERN_API_KEY}`,
    ...(options.headers || {})
  };
  return fetch(url, { ...options, headers });
}

function pickArrayPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  for (const key of ['characters', 'data', 'results', 'items', 'list']) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  return [];
}

async function fetchSillyCharacters() {
  const explicit = SILLYTAVERN_CHARACTERS_URL || '';
  const probes = explicit ? [explicit] : ['/api/characters', '/api/characters/list', '/api/v1/characters', '/api/char/list', '/characters'];
  const errors = [];

  for (const probe of probes) {
    try {
      const res = await stRequest(probe, { method: 'GET' });
      if (!res.ok) {
        errors.push(`${probe}: ${res.status}`);
        continue;
      }
      const data = await res.json().catch(() => null);
      const rows = pickArrayPayload(data);
      if (rows.length > 0) return rows;
      errors.push(`${probe}: empty`);
    } catch (err) {
      errors.push(`${probe}: ${err.message || String(err)}`);
    }
  }
  throw new Error(`Could not fetch SillyTavern characters (${errors.join(' | ')})`);
}

function normalizeCharacter(raw) {
  const name = String(raw?.name || raw?.char_name || raw?.display_name || raw?.title || '').trim();
  if (!name) return null;
  const sourceId = String(raw?.id || raw?.uuid || raw?.character_id || raw?.char_id || slugify(name)).trim();
  const description = String(raw?.description || raw?.persona || raw?.personality || raw?.bio || '').trim();
  const scenario = String(raw?.scenario || raw?.context || '').trim();
  const greeting = String(raw?.first_mes || raw?.greeting || raw?.welcome || '').trim();
  const statusText = String(raw?.status || raw?.tagline || raw?.mood || 'SillyTavern Character').trim();
  const avatarUrl = String(raw?.avatar_url || raw?.avatar || raw?.image || raw?.icon || '').trim();
  const bannerUrl = String(raw?.banner_url || raw?.banner || raw?.cover || '').trim();
  const roomId = String(raw?.room_id || raw?.room || raw?.chat_id || '').trim();
  const bioParts = [description, scenario ? `Scenario: ${scenario}` : '', greeting ? `Greeting: ${greeting}` : ''].filter(Boolean);

  return {
    source_id: sourceId,
    name: name.slice(0, 80),
    description: description.slice(0, 2000),
    bio: bioParts.join('\n\n').slice(0, 4000),
    status_text: statusText.slice(0, 120),
    avatar_url: isHttpUrl(avatarUrl) ? avatarUrl : '',
    banner_url: isHttpUrl(bannerUrl) ? bannerUrl : '',
    room_id: roomId.slice(0, 120)
  };
}

async function dcAdminRequest(pathname, options = {}, requireAuth = true) {
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };
  if (requireAuth && adminSessionCookie) headers.Cookie = adminSessionCookie;
  return fetch(`${DREAMCORD_BASE_URL}${pathname}`, { ...options, headers });
}

async function ensureAdminSession() {
  if (!DREAMCORD_ADMIN_USERNAME || !DREAMCORD_ADMIN_PASSWORD) {
    throw new Error('Missing DREAMCORD_ADMIN_USERNAME / DREAMCORD_ADMIN_PASSWORD');
  }

  if (adminSessionCookie) {
    const probe = await dcAdminRequest('/auth/me', { method: 'GET' }, true);
    if (probe.ok) return;
    adminSessionCookie = '';
  }

  const loginRes = await dcAdminRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: DREAMCORD_ADMIN_USERNAME, password: DREAMCORD_ADMIN_PASSWORD })
  }, false);

  if (loginRes.status === 202) {
    const data = await loginRes.json().catch(() => ({}));
    if (!DREAMCORD_ADMIN_2FA) throw new Error('Dreamcord admin requires 2FA. Set DREAMCORD_ADMIN_2FA.');
    const challengeId = String(data?.challenge_id || '').trim();
    if (!challengeId) throw new Error('2FA challenge id missing from login response.');
    const twofaRes = await dcAdminRequest('/auth/login/2fa', {
      method: 'POST',
      body: JSON.stringify({ challenge_id: challengeId, code: DREAMCORD_ADMIN_2FA })
    }, false);
    if (!twofaRes.ok) {
      const txt = await twofaRes.text();
      throw new Error(`2FA login failed: ${twofaRes.status} ${txt}`);
    }
    const cookie = extractCookieFromResponse(twofaRes, 'sessionId');
    if (!cookie) throw new Error('2FA login succeeded but no sessionId cookie returned.');
    adminSessionCookie = cookie;
    return;
  }

  if (!loginRes.ok) {
    const txt = await loginRes.text();
    throw new Error(`Admin login failed: ${loginRes.status} ${txt}`);
  }

  const cookie = extractCookieFromResponse(loginRes, 'sessionId');
  if (!cookie) throw new Error('Login succeeded but no sessionId cookie returned.');
  adminSessionCookie = cookie;
}

async function dcAdminJson(pathname, options = {}) {
  await ensureAdminSession();
  const res = await dcAdminRequest(pathname, options, true);
  if (res.status === 401 || res.status === 403) {
    adminSessionCookie = '';
    await ensureAdminSession();
    const retry = await dcAdminRequest(pathname, options, true);
    if (!retry.ok) {
      const txt = await retry.text();
      throw new Error(`Dreamcord admin ${options.method || 'GET'} ${pathname} failed: ${retry.status} ${txt}`);
    }
    return retry.json().catch(() => ({}));
  }
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Dreamcord admin ${options.method || 'GET'} ${pathname} failed: ${res.status} ${txt}`);
  }
  return res.json().catch(() => ({}));
}

async function dcBotPostToChannel(channelId, content) {
  if (!DREAMCORD_BOT_TOKEN || !channelId || !content) return null;
  const res = await fetch(`${DREAMCORD_BASE_URL}/bot/channels/${channelId}/messages`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bot ${DREAMCORD_BOT_TOKEN}`
    },
    body: JSON.stringify({ content: String(content), prefix: true })
  });
  if (!res.ok) return null;
  return res.json().catch(() => null);
}

function toAppPatch(character) {
  return {
    name: character.name,
    description: character.description || `Imported from ${DEFAULT_SOURCE_LABEL}`,
    bio: character.bio || '',
    status_text: character.status_text || 'SillyTavern Character',
    avatar_url: character.avatar_url || null,
    banner_url: character.banner_url || null,
    profile_source_label: DEFAULT_SOURCE_LABEL,
    profile_hide_room: false,
    nomi_room_default: character.room_id || null
  };
}

function buildSyncSummary(result) {
  return [
    `[SillyTavern Sync] total=${result.total}`,
    `created=${result.created.length}`,
    `updated=${result.updated.length}`,
    `unchanged=${result.unchanged.length}`,
    `missing=${result.missing_in_source.length}`
  ].join(' | ');
}

async function runCharacterSync(opts = {}) {
  if (!hasBridgeConfig()) {
    throw new Error('Bridge not configured. Fill env vars first.');
  }

  const dryRun = opts.dryRun === true;
  const createMissing = opts.createMissing !== false;
  const updateExisting = opts.updateExisting !== false;
  const disableMissing = opts.disableMissing === true;
  const targetChannelId = String(opts.targetChannelId || DEFAULT_TARGET_CHANNEL_ID || '').trim();

  const rawCharacters = await fetchSillyCharacters();
  const overrides = await loadCharacterOverrides();
  const normalized = rawCharacters
    .map(normalizeCharacter)
    .filter(Boolean)
    .map((c) => applyCharacterOverride(c, overrides[String(c.source_id)]));
  const dedup = new Map();
  normalized.forEach((c) => { if (!dedup.has(c.source_id)) dedup.set(c.source_id, c); });
  const sourceChars = Array.from(dedup.values());

  const map = await loadCharacterMap();
  const apps = await dcAdminJson('/admin/dev-portal/apps');
  const existing = Array.isArray(apps) ? apps : [];
  const byId = new Map(existing.map((a) => [String(a.id), a]));
  const byName = new Map(existing.map((a) => [String(a.name || '').toLowerCase(), a]));

  const result = {
    ok: true,
    dry_run: dryRun,
    total: sourceChars.length,
    created: [],
    updated: [],
    unchanged: [],
    missing_in_source: [],
    errors: []
  };

  for (const ch of sourceChars) {
    try {
      const mappedId = String(map[ch.source_id] || '').trim();
      let appRow = mappedId ? byId.get(mappedId) : null;
      if (!appRow) appRow = byName.get(ch.name.toLowerCase()) || null;

      if (!appRow) {
        if (!createMissing) {
          result.unchanged.push({ source_id: ch.source_id, name: ch.name, reason: 'create_missing=false' });
          continue;
        }
        if (dryRun) {
          result.created.push({ source_id: ch.source_id, name: ch.name, planned: true });
          continue;
        }
        const created = await dcAdminJson('/admin/dev-portal/apps', {
          method: 'POST',
          body: JSON.stringify({ ...toAppPatch(ch), owner_id: null })
        });
        const createdApp = created?.app || created;
        if (!createdApp?.id) throw new Error(`Create app failed for "${ch.name}"`);
        map[ch.source_id] = createdApp.id;
        byId.set(String(createdApp.id), createdApp);
        byName.set(ch.name.toLowerCase(), createdApp);
        result.created.push({ source_id: ch.source_id, app_id: createdApp.id, name: ch.name });
        continue;
      }

      map[ch.source_id] = appRow.id;
      if (!updateExisting) {
        result.unchanged.push({ source_id: ch.source_id, app_id: appRow.id, name: ch.name, reason: 'update_existing=false' });
        continue;
      }

      const patch = toAppPatch(ch);
      const changed =
        String(appRow.name || '') !== String(patch.name || '') ||
        String(appRow.description || '') !== String(patch.description || '') ||
        String(appRow.bio || '') !== String(patch.bio || '') ||
        String(appRow.status_text || '') !== String(patch.status_text || '') ||
        String(appRow.avatar_url || '') !== String(patch.avatar_url || '') ||
        String(appRow.banner_url || '') !== String(patch.banner_url || '') ||
        String(appRow.profile_source_label || '') !== String(patch.profile_source_label || '') ||
        Boolean(appRow.profile_hide_room) !== Boolean(patch.profile_hide_room) ||
        String(appRow.nomi_room_default || '') !== String(patch.nomi_room_default || '');

      if (!changed) {
        result.unchanged.push({ source_id: ch.source_id, app_id: appRow.id, name: ch.name, reason: 'no_changes' });
        continue;
      }

      if (dryRun) {
        result.updated.push({ source_id: ch.source_id, app_id: appRow.id, name: ch.name, planned: true });
        continue;
      }

      await dcAdminJson(`/admin/dev-portal/apps/${appRow.id}`, {
        method: 'PATCH',
        body: JSON.stringify(patch)
      });
      result.updated.push({ source_id: ch.source_id, app_id: appRow.id, name: ch.name });
    } catch (err) {
      result.errors.push({ source_id: ch.source_id, name: ch.name, error: err.message || String(err) });
    }
  }

  if (disableMissing) {
    const sourceIds = new Set(sourceChars.map((c) => String(c.source_id)));
    for (const [sourceId, appId] of Object.entries(map)) {
      if (sourceIds.has(String(sourceId))) continue;
      const row = byId.get(String(appId));
      if (!row) continue;
      if (dryRun) {
        result.missing_in_source.push({ source_id: sourceId, app_id: appId, name: row.name, planned_disable: true });
        continue;
      }
      await dcAdminJson(`/admin/dev-portal/apps/${appId}`, {
        method: 'PATCH',
        body: JSON.stringify({ is_active: false })
      });
      result.missing_in_source.push({ source_id: sourceId, app_id: appId, name: row.name, disabled: true });
    }
  }

  if (!dryRun) {
    await saveCharacterMap(map);
    if (targetChannelId) {
      const posted = await dcBotPostToChannel(targetChannelId, buildSyncSummary(result));
      result.posted_message_id = posted?.id || null;
    }
  }

  return result;
}

async function init(router) {
  router.get('/health', (_req, res) => {
    res.json({ ok: true, configured: hasBridgeConfig(), plugin: 'dreamcord-sillytavern-bridge' });
  });

  router.get('/config', (_req, res) => {
    res.json({
      dreamcord_base_url: DREAMCORD_BASE_URL || null,
      sillytavern_base_url: SILLYTAVERN_BASE_URL || null,
      source_label: DEFAULT_SOURCE_LABEL,
      configured: hasBridgeConfig()
    });
  });

  router.get('/mappings', async (_req, res) => {
    try {
      const map = await loadCharacterMap();
      res.json({ ok: true, mappings: map });
    } catch (err) {
      res.status(500).json({ error: err.message || 'Could not read mappings' });
    }
  });

  router.get('/characters/preview', async (_req, res) => {
    try {
      if (!hasBridgeConfig()) {
        return res.status(400).json({ error: 'Bridge not configured. Fill env vars first.' });
      }
      const [rawCharacters, map, overrides, apps] = await Promise.all([
        fetchSillyCharacters(),
        loadCharacterMap(),
        loadCharacterOverrides(),
        dcAdminJson('/admin/dev-portal/apps')
      ]);
      const appList = Array.isArray(apps) ? apps : [];
      const byId = new Map(appList.map((a) => [String(a.id), a]));
      const byName = new Map(appList.map((a) => [String(a.name || '').toLowerCase(), a]));
      const rows = rawCharacters
        .map(normalizeCharacter)
        .filter(Boolean)
        .map((c) => {
          const sourceId = String(c.source_id);
          const override = overrides[sourceId] || null;
          const merged = applyCharacterOverride(c, override);
          const mappedId = String(map[sourceId] || '').trim();
          const app = mappedId ? byId.get(mappedId) : (byName.get(String(merged.name || '').toLowerCase()) || null);
          return {
            source_id: sourceId,
            character: merged,
            override,
            mapped_app_id: app?.id || mappedId || null,
            mapped_app_name: app?.name || null,
            mapped_active: app?.is_active === true
          };
        });
      res.json({ ok: true, total: rows.length, rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message || 'Could not build preview' });
    }
  });

  router.put('/characters/:sourceId/override', async (req, res) => {
    try {
      const sourceId = String(req.params.sourceId || '').trim();
      if (!sourceId) return res.status(400).json({ error: 'sourceId is required' });
      const patch = sanitizeCharacterOverride(req.body || {});
      const overrides = await loadCharacterOverrides();
      const next = { ...(overrides[sourceId] || {}), ...patch };
      const compact = Object.fromEntries(
        Object.entries(next).filter(([, v]) => v !== undefined && v !== null && String(v) !== '')
      );
      if (Object.keys(compact).length === 0) {
        delete overrides[sourceId];
      } else {
        overrides[sourceId] = compact;
      }
      await saveCharacterOverrides(overrides);
      res.json({ ok: true, source_id: sourceId, override: overrides[sourceId] || null });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message || 'Could not save override' });
    }
  });

  router.delete('/characters/:sourceId/override', async (req, res) => {
    try {
      const sourceId = String(req.params.sourceId || '').trim();
      if (!sourceId) return res.status(400).json({ error: 'sourceId is required' });
      const overrides = await loadCharacterOverrides();
      delete overrides[sourceId];
      await saveCharacterOverrides(overrides);
      res.json({ ok: true, source_id: sourceId });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message || 'Could not clear override' });
    }
  });

  router.post('/sync/characters', async (req, res) => {
    try {
      const result = await runCharacterSync({
        dryRun: req.query.dry_run === '1' || req.body?.dry_run === true,
        createMissing: req.body?.create_missing !== false,
        updateExisting: req.body?.update_existing !== false,
        disableMissing: req.body?.disable_missing === true,
        targetChannelId: String(req.body?.target_channel_id || '').trim()
      });
      res.json(result);
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message || 'Sync failed' });
    }
  });

  console.log('[dreamcord-sillytavern-bridge] plugin initialized');
}

async function exit() {
  console.log('[dreamcord-sillytavern-bridge] plugin unloaded');
}

module.exports = {
  init,
  exit,
  info: {
    id: 'dreamcord-sillytavern-bridge',
    name: 'Dreamcord SillyTavern Bridge',
    description: 'Sync SillyTavern characters into Dreamcord Dev Portal bot apps.'
  }
};
