import 'dotenv/config';
import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
app.use(express.json({ limit: '4mb' }));

// CORS — allow SillyTavern frontend (any origin) to call this standalone server
app.use((_req, res, next) => {
  res.header('Access-Control-Allow-Origin', _req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token,x-api-key');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (_req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '..', 'data');
const MAP_PATH = path.join(DATA_DIR, 'character-map.json');
const OVERRIDES_PATH = path.join(DATA_DIR, 'character-overrides.json');

const PORT = Number(process.env.PORT || 3710);
const DREAMCORD_BASE_URL = String(process.env.DREAMCORD_BASE_URL || '').replace(/\/$/, '');
const DREAMCORD_BOT_TOKEN = String(process.env.DREAMCORD_BOT_TOKEN || '');
const DREAMCORD_ADMIN_USERNAME = String(process.env.DREAMCORD_ADMIN_USERNAME || '').trim();
const DREAMCORD_ADMIN_PASSWORD = String(process.env.DREAMCORD_ADMIN_PASSWORD || '');
const DREAMCORD_ADMIN_2FA = String(process.env.DREAMCORD_ADMIN_2FA || '').trim();
const SILLYTAVERN_BASE_URL = String(process.env.SILLYTAVERN_BASE_URL || '').replace(/\/$/, '');
const SILLYTAVERN_API_KEY = String(process.env.SILLYTAVERN_API_KEY || '').trim();
const SILLYTAVERN_USERNAME = String(process.env.SILLYTAVERN_USERNAME || '').trim();
const SILLYTAVERN_PASSWORD = String(process.env.SILLYTAVERN_PASSWORD || '');
const SILLYTAVERN_CHARACTERS_URL = String(process.env.SILLYTAVERN_CHARACTERS_URL || '').trim();
const DEFAULT_TARGET_CHANNEL_ID = String(process.env.DEFAULT_TARGET_CHANNEL_ID || '').trim();
const DEFAULT_SOURCE_LABEL = String(process.env.DEFAULT_SOURCE_TAG || 'sillytavern').trim().slice(0, 40) || 'sillytavern';

let adminSessionCookie = '';
let stSessionCookie = '';
let stCsrfToken = '';

function hasBridgeConfig() {
  return !!(DREAMCORD_BASE_URL && SILLYTAVERN_BASE_URL && DREAMCORD_ADMIN_USERNAME && DREAMCORD_ADMIN_PASSWORD);
}

async function ensureStSession() {
  if (stSessionCookie && stCsrfToken) return;
  // Get CSRF token
  const csrfRes = await fetch(`${SILLYTAVERN_BASE_URL}/csrf-token`);
  if (!csrfRes.ok) throw new Error(`ST CSRF fetch failed: ${csrfRes.status}`);
  const csrfData = await csrfRes.json();
  stCsrfToken = csrfData.token || '';
  const initCookies = csrfRes.headers.getSetCookie().map(c => String(c).split(';')[0]).join('; ');
  // Login
  if (SILLYTAVERN_USERNAME && SILLYTAVERN_PASSWORD) {
    const loginRes = await fetch(`${SILLYTAVERN_BASE_URL}/api/users/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': stCsrfToken, Cookie: initCookies },
      body: JSON.stringify({ handle: SILLYTAVERN_USERNAME, password: SILLYTAVERN_PASSWORD })
    });
    if (!loginRes.ok) throw new Error(`ST login failed: ${loginRes.status}`);
    stSessionCookie = loginRes.headers.getSetCookie().map(c => String(c).split(';')[0]).join('; ');
    // Refresh CSRF after login
    const csrf2Res = await fetch(`${SILLYTAVERN_BASE_URL}/csrf-token`, { headers: { Cookie: stSessionCookie } });
    if (csrf2Res.ok) stCsrfToken = (await csrf2Res.json()).token || stCsrfToken;
  } else {
    stSessionCookie = initCookies;
  }
}

function isHttpUrl(value) {
  const s = String(value || '').trim();
  return /^https?:\/\//i.test(s);
}

function parseRoomIdList(value) {
  if (Array.isArray(value)) {
    return Array.from(new Set(
      value.map((v) => String(v || '').trim()).filter(Boolean)
    )).slice(0, 64);
  }
  return Array.from(new Set(
    String(value || '')
      .split(/[\n,]+/)
      .map((v) => String(v || '').trim())
      .filter(Boolean)
  )).slice(0, 64);
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
  const parseIntBounded = (value, fallback, min, max) => {
    const n = Number.parseInt(String(value ?? '').trim(), 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.max(min, Math.min(max, n));
  };
  if (src.name !== undefined) next.name = String(src.name || '').trim().slice(0, 80);
  if (src.description !== undefined) next.description = String(src.description || '').trim().slice(0, 2000);
  if (src.bio !== undefined) next.bio = String(src.bio || '').trim().slice(0, 4000);
  if (src.status_text !== undefined) next.status_text = String(src.status_text || '').trim().slice(0, 120);
  if (src.room_ids !== undefined) next.room_ids = parseRoomIdList(src.room_ids);
  if (src.room_id !== undefined) {
    const first = parseRoomIdList(src.room_id)[0] || '';
    next.room_id = first.slice(0, 120);
    if (src.room_ids === undefined && first) next.room_ids = [first];
  }
  if (src.room_ids !== undefined && !next.room_id) {
    const first = (next.room_ids && next.room_ids[0]) ? String(next.room_ids[0]) : '';
    next.room_id = first.slice(0, 120);
  }
  if (src.bot_token !== undefined) next.bot_token = String(src.bot_token || '').trim().slice(0, 512);
  if (src.memory_enabled !== undefined) next.memory_enabled = Boolean(src.memory_enabled);
  if (src.memory_messages !== undefined) next.memory_messages = parseIntBounded(src.memory_messages, 6, 0, 20);
  return next;
}

function applyCharacterOverride(character, override) {
  if (!override || typeof override !== 'object') return character;
  const mergedRoomIds = parseRoomIdList(
    override.room_ids !== undefined ? override.room_ids : (character.room_ids || '')
  );
  if (!mergedRoomIds.length) {
    const fallback = parseRoomIdList(override.room_id !== undefined ? override.room_id : character.room_id);
    fallback.forEach((v) => mergedRoomIds.push(v));
  }
  const resolvedRoomId = String(
    override.room_id !== undefined
      ? (parseRoomIdList(override.room_id)[0] || '')
      : (character.room_id || mergedRoomIds[0] || '')
  ).slice(0, 120);
  return {
    ...character,
    name: override.name !== undefined && override.name !== '' ? String(override.name).trim().slice(0, 80) : character.name,
    description: override.description !== undefined ? String(override.description || '').trim().slice(0, 2000) : character.description,
    bio: override.bio !== undefined ? String(override.bio || '').trim().slice(0, 4000) : character.bio,
    status_text: override.status_text !== undefined ? String(override.status_text || '').trim().slice(0, 120) : character.status_text,
    room_ids: mergedRoomIds,
    room_id: resolvedRoomId,
    bot_token: override.bot_token !== undefined ? String(override.bot_token || '').trim().slice(0, 512) : (character.bot_token || ''),
    memory_enabled: override.memory_enabled !== false,
    memory_messages: (() => {
      const n = Number.parseInt(String(override.memory_messages ?? 6), 10);
      if (!Number.isFinite(n)) return 6;
      return Math.max(0, Math.min(20, n));
    })()
  };
}

async function stRequest(pathOrUrl, options = {}) {
  await ensureStSession();
  const isAbsolute = isHttpUrl(pathOrUrl);
  const url = isAbsolute ? String(pathOrUrl) : `${SILLYTAVERN_BASE_URL}${pathOrUrl.startsWith('/') ? '' : '/'}${pathOrUrl}`;
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    ...(SILLYTAVERN_API_KEY ? { 'x-api-key': SILLYTAVERN_API_KEY, Authorization: `Bearer ${SILLYTAVERN_API_KEY}` } : {}),
    ...(stSessionCookie ? { Cookie: stSessionCookie } : {}),
    ...(stCsrfToken ? { 'X-CSRF-Token': stCsrfToken } : {}),
    ...(options.headers || {})
  };
  const res = await fetch(url, { ...options, headers });
  // If 403, session may have expired — clear and retry once
  if (res.status === 403 && stSessionCookie) {
    stSessionCookie = '';
    stCsrfToken = '';
    await ensureStSession();
    const retryHeaders = { ...headers, Cookie: stSessionCookie, 'X-CSRF-Token': stCsrfToken };
    return fetch(url, { ...options, headers: retryHeaders });
  }
  return res;
}

function pickArrayPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  const candidates = ['characters', 'data', 'results', 'items', 'list'];
  for (const key of candidates) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  return [];
}

async function fetchSillyCharacters() {
  const explicit = SILLYTAVERN_CHARACTERS_URL || '';
  const probes = explicit
    ? [{ path: explicit, method: 'GET' }]
    : [
        { path: '/api/characters/all', method: 'POST' },
        { path: '/api/characters', method: 'GET' },
        { path: '/api/characters/list', method: 'GET' },
        { path: '/api/v1/characters', method: 'GET' },
        { path: '/api/char/list', method: 'GET' },
        { path: '/characters', method: 'GET' }
      ];

  const errors = [];
  for (const probe of probes) {
    try {
      const res = await stRequest(probe.path, { method: probe.method });
      if (!res.ok) {
        errors.push(`${probe.path}: ${res.status}`);
        continue;
      }
      const data = await res.json().catch(() => null);
      const rows = pickArrayPayload(data);
      if (rows.length > 0) return rows;
      errors.push(`${probe.path}: empty`);
    } catch (err) {
      errors.push(`${probe.path}: ${err.message || String(err)}`);
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
  if (requireAuth && adminSessionCookie) {
    headers.Cookie = adminSessionCookie;
  }
  const res = await fetch(`${DREAMCORD_BASE_URL}${pathname}`, { ...options, headers });
  return res;
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
    body: JSON.stringify({
      username: DREAMCORD_ADMIN_USERNAME,
      password: DREAMCORD_ADMIN_PASSWORD
    })
  }, false);

  if (loginRes.status === 202) {
    const data = await loginRes.json().catch(() => ({}));
    if (!DREAMCORD_ADMIN_2FA) {
      throw new Error('Dreamcord admin requires 2FA. Set DREAMCORD_ADMIN_2FA.');
    }
    const challengeId = String(data?.challenge_id || '').trim();
    if (!challengeId) throw new Error('2FA challenge id missing from login response.');
    const twofaRes = await dcAdminRequest('/auth/login/2fa', {
      method: 'POST',
      body: JSON.stringify({
        challenge_id: challengeId,
        code: DREAMCORD_ADMIN_2FA
      })
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

async function dcAdminAppsListSafe() {
  try {
    const apps = await dcAdminJson('/admin/dev-portal/apps');
    return { apps: Array.isArray(apps) ? apps : [], warning: '' };
  } catch (err) {
    const msg = String(err?.message || err || 'unknown error');
    console.warn(`[dreamcord-bot-bridge] app list unavailable: ${msg}`);
    return { apps: [], warning: msg };
  }
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
    profile_source_label: DEFAULT_SOURCE_LABEL,
    profile_hide_room: false,
    nomi_room_default: character.room_id || null
  };
}

function buildSyncSummary(result) {
  const parts = [];
  parts.push(`[SillyTavern Sync] total=${result.total}`);
  parts.push(`created=${result.created.length}`);
  parts.push(`updated=${result.updated.length}`);
  parts.push(`unchanged=${result.unchanged.length}`);
  parts.push(`missing=${result.missing_in_source.length}`);
  return parts.join(' | ');
}

// --- Routes ---

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'dreamcord-bot-bridge', configured: hasBridgeConfig() });
});

app.get('/config', (_req, res) => {
  res.json({
    dreamcord_base_url: DREAMCORD_BASE_URL || null,
    sillytavern_base_url: SILLYTAVERN_BASE_URL || null,
    source_label: DEFAULT_SOURCE_LABEL,
    configured: hasBridgeConfig()
  });
});

app.get('/mappings', async (_req, res) => {
  try {
    const map = await loadCharacterMap();
    res.json({ ok: true, mappings: map });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Could not read mappings' });
  }
});

app.get('/characters/preview', async (_req, res) => {
  try {
    if (!hasBridgeConfig()) {
      return res.status(400).json({ error: 'Bridge not configured. Fill env vars first.' });
    }
    const [rawCharacters, map, overrides] = await Promise.all([
      fetchSillyCharacters(),
      loadCharacterMap(),
      loadCharacterOverrides()
    ]);
    const { apps: appList, warning: appsWarning } = await dcAdminAppsListSafe();
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
    res.json({ ok: true, total: rows.length, rows, apps_warning: appsWarning || null });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || 'Could not build preview' });
  }
});

app.put('/characters/:sourceId/override', async (req, res) => {
  try {
    const sourceId = String(req.params.sourceId || '').trim();
    if (!sourceId) return res.status(400).json({ error: 'sourceId is required' });
    const patch = sanitizeCharacterOverride(req.body || {});
    const overrides = await loadCharacterOverrides();
    const next = { ...(overrides[sourceId] || {}), ...patch };
    delete next.api_key;
    delete next.avatar_url;
    delete next.banner_url;
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

app.delete('/characters/:sourceId/override', async (req, res) => {
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

app.post('/sync/characters', async (req, res) => {
  try {
    if (!hasBridgeConfig()) {
      return res.status(400).json({ error: 'Bridge not configured. Fill env vars first.' });
    }

    const dryRun = req.query.dry_run === '1' || req.body?.dry_run === true;
    const createMissing = req.body?.create_missing !== false;
    const updateExisting = req.body?.update_existing !== false;
    const disableMissing = req.body?.disable_missing === true;
    const targetChannelId = String(req.body?.target_channel_id || DEFAULT_TARGET_CHANNEL_ID || '').trim();

    const rawCharacters = await fetchSillyCharacters();
    const overrides = await loadCharacterOverrides();
    const normalized = rawCharacters
      .map(normalizeCharacter)
      .filter(Boolean)
      .map((c) => applyCharacterOverride(c, overrides[String(c.source_id)]));
    const dedup = new Map();
    normalized.forEach((c) => {
      const key = String(c.source_id || slugify(c.name));
      if (!dedup.has(key)) dedup.set(key, c);
    });
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
        const hasMeaningfulChange =
          String(appRow.name || '') !== String(patch.name || '') ||
          String(appRow.description || '') !== String(patch.description || '') ||
          String(appRow.bio || '') !== String(patch.bio || '') ||
          String(appRow.status_text || '') !== String(patch.status_text || '') ||
          String(appRow.profile_source_label || '') !== String(patch.profile_source_label || '') ||
          Boolean(appRow.profile_hide_room) !== Boolean(patch.profile_hide_room) ||
          String(appRow.nomi_room_default || '') !== String(patch.nomi_room_default || '');

        if (!hasMeaningfulChange) {
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
        const msg = buildSyncSummary(result);
        const posted = await dcBotPostToChannel(targetChannelId, msg);
        result.posted_message_id = posted?.id || null;
      }
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || 'Sync failed' });
  }
});

app.listen(PORT, () => {
  console.log(`[Bridge] listening on :${PORT}`);
  console.log(`[Bridge] configured=${hasBridgeConfig()}`);
});
