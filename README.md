# Dreamcord Bot Bridge (v0.2.0)

Syncs SillyTavern characters into Dreamcord Dev Portal bot apps with per-character overrides (name, description, bio, status, avatar, banner, room/channel scope, bot token).

## Install modes

### 1. Standalone bridge server (recommended)

Runs as its own Express service on port 3710. The SillyTavern frontend extension auto-detects it — no ST server plugin loading needed.

### 2. SillyTavern server plugin

If your ST instance has `enableServerPlugins: true` in `config.yaml`, you can install `sillytavern-plugin/` into `<ST>/plugins/dreamcord-bot-bridge/`. See `sillytavern-plugin/README.md`.

### 3. Frontend extension only

The root `manifest.json` + `index.js` can be installed as an ST URL extension. The extension UI auto-probes for the backend (ST plugin path first, then standalone on ports 3710/3711).

## Quick start (standalone)

```powershell
cd d:\webview\Dreamuniverse\dreamcord-bot-bridge
copy .env.example .env
# Fill .env with your credentials
npm install
npm run dev
```

Test: `curl http://127.0.0.1:3710/health`

## Required env vars

| Variable | Required | Description |
|---|---|---|
| `DREAMCORD_BASE_URL` | Yes | e.g. `https://dreamcord.interitium.dk/api` |
| `DREAMCORD_ADMIN_USERNAME` | Yes | Admin account for Dev Portal API |
| `DREAMCORD_ADMIN_PASSWORD` | Yes | Admin password |
| `SILLYTAVERN_BASE_URL` | Yes | e.g. `http://127.0.0.1:8000` |
| `SILLYTAVERN_API_KEY` | Optional | ST API key (or use `SILLYTAVERN_USERNAME` + `SILLYTAVERN_PASSWORD`) |
| `DREAMCORD_ADMIN_2FA` | If 2FA | TOTP code (or static secret) |
| `DREAMCORD_BOT_TOKEN` | No | For posting sync summaries to a channel |
| `DEFAULT_TARGET_CHANNEL_ID` | No | Channel to post sync summaries |
| `DEFAULT_SOURCE_TAG` | No | Label for imported apps (default: `sillytavern`) |
| `SILLYTAVERN_CHARACTERS_URL` | No | Override ST character endpoint |

## API endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/config` | Current bridge config (no secrets) |
| GET | `/mappings` | Source-to-app ID map |
| GET | `/characters/preview` | Fetch ST characters + Dreamcord app mapping + overrides |
| PUT | `/characters/:sourceId/override` | Save per-character override fields |
| DELETE | `/characters/:sourceId/override` | Clear override for a character |
| POST | `/sync/characters` | Run full sync (create/update/disable apps) |

### Sync body example

```json
{
  "dry_run": false,
  "target_channel_id": "<optional dreamcord channel uuid>",
  "create_missing": true,
  "update_existing": true,
  "disable_missing": false
}
```

## Per-character overrides

Each character supports these override fields (set via the extension UI or API):
- `name`, `description`, `bio`, `status_text`
- `avatar_url`, `banner_url`
- `room_id` / `room_ids` — restrict responder to one or more Dreamcord channel IDs
- `bot_token` — per-character Dreamcord bot token
- `responder_enabled`, `respond_any_message`, `trigger_keyword`
- `memory_enabled`, `memory_messages` — optional recent-room context injection for better reply continuity

Override data persists in `data/character-overrides.json`.

## Data files

- `data/character-map.json` — source ID to Dreamcord app ID mapping
- `data/character-overrides.json` — per-character field overrides

## SillyTavern character fetch probes

When `SILLYTAVERN_CHARACTERS_URL` is not set, the bridge probes these endpoints in order:
- `/api/characters`
- `/api/characters/list`
- `/api/v1/characters`
- `/api/char/list`
- `/characters`
