# Vine (Bloom Watcher) — org.bloom.Vine

A minimal Tauri + Rust app that watches `~/Bloom/Public` and `~/Bloom/Private`.
- Files in **Public** are uploaded as-is.
- Files in **Private** are encrypted locally with AES-GCM before upload.
- Each file (by content hash) is uploaded **once per server**, even if it remains in the folder.
- No metadata edits unless the user opens the app and does manual actions (not included in this skeleton).

> NOTE: This is a working scaffold. You can extend the UI and implement NIP-98/NIP-46 auth later.
> The Blossom/NIP-96 upload endpoint here is a simple `POST {server}/upload` placeholder.

## Build (Dev)

1) Install prerequisites: Rust toolchain, Node 20+, pnpm/npm, Tauri deps.
2) Install JS deps:
```bash
pnpm i
```
3) Run dev:
```bash
pnpm tauri dev
```
4) Build:
```bash
pnpm tauri build
```

## Config

Servers are read from `~/.config/VineWatcher/servers.json`:

```json
{ "servers": ["https://blossom.example"] }
```

On first run the app creates:
- `~/Bloom/Public`
- `~/Bloom/Private`
- `~/.config/VineWatcher/state.sqlite` (upload ledger)

## Flatpak

Manifest: `org.bloom.Vine.json`

```bash
flatpak-builder --user --force-clean build-dir org.bloom.Vine.json
flatpak-builder --user --install build-dir org.bloom.Vine.json
flatpak run org.bloom.Vine
```

## License

MIT
