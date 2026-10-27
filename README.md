# Telegram Companion updates

Public signed **macOS arm64 binary updates only**. Application source remains private.

The first verified public updater release is [v0.2.2](https://github.com/qinsehm1128/tg-companion-updates/releases/tag/v0.2.2).
An existing v0.1.0 application must be upgraded manually once. Later stable
`vMAJOR.MINOR.PATCH` releases are offered at:

https://github.com/qinsehm1128/tg-companion-updates/releases/latest/download/latest.json

Bundles are Tauri/minisign authenticated against the checked-in public key. They use
ad-hoc macOS code signing, **not Apple Developer ID signing or notarization**.

Repository main contains only this README, `.github/workflows/publish.yml`,
`scripts/verify-update.py`, and `scripts/updater-public-key.txt`.
Private source CI pushes a **new tag only**, using a write deploy key scoped to this
public repository; it does not modify main or force tags. Each tag adds an `assets/`
directory with exactly one `.app.tar.gz`, its `.sig`, and `latest.json`. Public git
therefore retains each released binary archive. No account data, databases, debug
artifacts or private source are permitted.

The public tag-triggered workflow verifies the stable tag, archive/resource allowlist,
100 MiB compressed cap, metadata URLs/hash/size and full minisign signature. Using this
repository's own `GITHUB_TOKEN`, it creates a draft Release, uploads all three files,
checks asset inventory and sizes, then publishes. Failed uploads remain draft. Already
published tags are never overwritten. Older stable versions do not replace latest.

## Initialization mapping (maintainer only)

Copy only these reviewed templates from private `scripts/update-repository/`:

- `README.md` → `README.md`
- `publish.yml` → `.github/workflows/publish.yml`
- `verify-update.py` → `scripts/verify-update.py`
- `updater-public-key.txt` → `scripts/updater-public-key.txt`

Do not copy the private repository, node_modules, native sources, or signing keys.
No PAT is required: source has `TAURI_SIGNING_PRIVATE_KEY` and repository-specific
`UPDATES_DEPLOY_KEY`; receiver uses its own repository token.
