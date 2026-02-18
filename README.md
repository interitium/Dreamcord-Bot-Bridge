# Dreamcord SillyTavern Bridge (v0.1.0)

This project supports two install modes:

1. Standalone local service (`src/index.js`)
2. SillyTavern server plugin extension (`sillytavern-plugin/`) for GitHub/local install

## What is included now

- Node + Express service scaffold
- Health/config endpoints
- Real `POST /sync/characters` flow:
  - fetch SillyTavern characters
  - normalize character payloads
  - create/update Dreamcord Dev Portal bot apps
  - optional disable of missing source characters
  - local source-id to app-id mapping persistence
- Dreamcord bot-post helper for sync summary notifications
- Env-driven configuration

## Folder

`d:\webview\Dreamuniverse\dreamcord-sillytavern-bridge`

Plugin extension folder:

`d:\webview\Dreamuniverse\dreamcord-sillytavern-bridge\sillytavern-plugin`

## Quick start (standalone)

1. Copy env template:

```powershell
cd d:\webview\Dreamuniverse\dreamcord-sillytavern-bridge
copy .env.example .env
```

2. Fill required values in `.env`:

- `DREAMCORD_BASE_URL`
- `DREAMCORD_ADMIN_USERNAME`
- `DREAMCORD_ADMIN_PASSWORD`
- `DREAMCORD_ADMIN_2FA` (optional, required only if admin uses 2FA)
- `SILLYTAVERN_BASE_URL`
- `SILLYTAVERN_API_KEY`
- `DREAMCORD_BOT_TOKEN` (optional, only for posting sync summary into channel)

3. Install and run:

```powershell
npm install
npm run dev
```

4. Test health:

```powershell
curl http://127.0.0.1:3710/health
```

## Endpoints

- `GET /health`
- `GET /config`
- `GET /mappings`
- `POST /sync/characters?dry_run=1`

Body example:

```json
{
  "target_channel_id": "<optional dreamcord channel uuid>",
  "create_missing": true,
  "update_existing": true,
  "disable_missing": false
}
```

## Plugin extension install

See:

`./sillytavern-plugin/README.md`

## Notes

- Mapping file path:
  - `data/character-map.json`
- Current SillyTavern fetch probes (when `SILLYTAVERN_CHARACTERS_URL` is not set):
  - `/api/characters`
  - `/api/characters/list`
  - `/api/v1/characters`
  - `/api/char/list`
  - `/characters`


## URL extension install (manifest)
This repo now contains root \\manifest.json\\ and \\index.js\\ so SillyTavern URL install succeeds.
For sync APIs, also install \\sillytavern-plugin/\\ into SillyTavern server plugins.
