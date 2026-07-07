# A Trader's Tool — Windows desktop app

A lightweight Electron shell that opens https://atraderstool.com in a dedicated
window. All features live on the website — every web release appears in the
desktop app automatically. The shell itself (window/tray/Electron) auto-updates
too when installed via the installer (see below).

## Features
- **Multi-window workspace**: pop any of 11 features (My Wallets, Sniffing Tool,
  Splashes, Arbitrage, Oracle Price, Mark vs Last, Index vs Last, Stock arbitrage,
  Big Limits, NATR Screener, Listings & Delistings) into its own OS window via the
  ⧉ button next to it in the sidebar. Each window shows only that feature (no
  sidebar), shares the single login, and its open state + size/position are saved
  automatically and reopened on the next launch (surviving app & PC restarts).
  Reopening a feature that already has a window focuses it instead of duplicating.
  Each window is an independent top-level window (v1.1.3+): clicking one no longer
  raises the whole app group above other applications.
- **App-activation raise (v1.1.5+)**: when you return to the app from another
  program and click any one of its windows, **all** open app windows (main +
  every feature pop-out) come to the foreground together, above the other app —
  your whole monitoring layout surfaces at once. This is z-order only (macOS-style
  app activation): within the app, clicking a specific window still brings just
  that one topmost with the others right behind it, and windows stay independently
  movable (no pinning/drag-together). Minimized or tray-hidden windows are left as
  they are. Works whether or not the windows are snapped.
- **Ctrl+scroll page zoom (v1.1.3+)**: Ctrl+mouse-wheel zooms the page in/out in
  any window (step 0.1, clamped 0.5–2.5×); Ctrl+0 resets to 100%. The panel's own
  Ctrl+wheel areas (Terminal DOM board, splash chart zoom) keep working unchanged.
- **User-configurable network proxy (v1.1.8+)**: route **all** desktop-app
  traffic — the panel, the Terminal's browser-direct Phemex market-data WebSocket
  and everything else — through a local proxy on the user's PC (SOCKS5 or HTTP,
  e.g. a Shadowsocks client at `127.0.0.1:2080`). Solves geo-blocking: the
  Terminal DOM's live data comes straight from the exchange, so only the desktop
  shell can tunnel it. Configured on the panel's "🖥️ Desktop App" page (Type +
  host + port → Save & enable); the setting persists across restarts and is
  applied to every session before the first window loads. Applying reloads all
  windows so connections re-open through the proxy. **Escape hatches** so a bad
  proxy can never lock the user out: a tray submenu ("Network proxy → Enable /
  Disable / Proxy settings…") and a "Disable proxy & retry" button on the offline
  screen both clear the proxy with no files or reinstall. Proxy auth
  (username/password) is not supported; usernames/passwords are never accepted.
- Persistent login (cookies survive restarts), remembers window size/position
- Closing the main window quits the whole app (and closes every feature window with it)
- System tray: Show/Hide, Quit, and a "Launch on startup" toggle (default OFF)
- Native Windows notifications (the site's alert notifications pop as normal Windows toasts)
- Single instance — launching it again just focuses the existing window
- External links open in your default browser; the window itself stays on atraderstool.com
- Offline → a retry screen instead of a blank white window (auto-retries every 15s)
- Ctrl+R reloads, Ctrl+Shift+I opens devtools
- **Auto-update (installer builds only)**: the installed app checks a release
  feed on launch, every hour, and (throttled to once per ~10 min) whenever a
  window gains focus, downloads updates in the background and installs them
  silently on the next quit. A tray menu item shows the update state
  ("Check for updates" / "Downloading…" / "Restart to update").
- **In-window "Update available" bar (installer builds only, v1.1.2+)**: when a
  new release is downloading/ready, a slim bar spans the top of the window
  ("⬇ Downloading update…" then "⭯ Update to vX available — click to restart &
  update"). Clicking the ready bar restarts the app and installs the update;
  a ✕ dismisses it for the session (the update still installs on quit).
  Shown on **every** window — the main window and every feature pop-out
  (v1.1.4+) — so a user working only in a pop-out still sees it (dismiss is
  per-window). Never shown in dev/portable builds.

## Two ways to run it (for users)

### 1. Installer (recommended — keeps itself up to date)
Run `A-Traders-Tool-<version>-setup.exe`. It's a one-click, per-user install
(no admin rights needed). The app then updates itself automatically whenever
a new shell version is published.

### 2. Portable exe (no install)
`A-Traders-Tool-<version>-portable.exe` needs no installation — just run it.
It **cannot self-update**; to get a newer shell you download a newer exe.
(Website features always stay current in both — the shell is just a window.)

⚠️ **Windows SmartScreen** will warn on first run because the exe is not
code-signed. Click **"More info" → "Run anyway"**. This is expected for
unsigned apps.

Staying unsigned is a deliberate decision (July 2026) — code-signing
certificates are paid and were declined for now. If that changes later, the
options are: **Azure Trusted Signing** (~$10/month, best SmartScreen result,
signable from Linux via a jsign-based hook in electron-builder), an **OV
certificate** (~$200–400/yr, warning fades over weeks as reputation builds),
or an **EV certificate** (~$300–600/yr). Signing would be wired in via
`build.win` signing options in `package.json`.

## Where releases are built (real Windows CI — canonical since v1.1.9)

Release installers are built on a **real `windows-latest` GitHub Actions
runner** with the standard electron-builder toolchain (real NSIS — the genuine
Windows uninstaller extraction, no sandbox workaround). This replaced the old
Replit-Linux build path, which packaged the NSIS uninstaller with a pure-JS
reader (`scripts/patch-nsis-uninstaller-reader.js` + `NSIS_UNINSTALLER_READER=1`)
because the sandbox cannot execute 32-bit code. That workaround could produce an
installer whose files looked right but failed at real-PC update time
("old removed, new not installed"). **It must no longer be used for releases.**
The patch script is kept only for optional local sandbox smoke builds; releases
never touch it.

This `desktop/` folder is the **single source of truth**. It is synced to the
GitHub repo **`att-desktop-releases`**, which holds these files, runs the CI, AND
is the public Releases feed — see "Source repo & CI" below. (An older separate
`att-desktop` source repo is **deprecated and unused** — it has no workflows, so
tagging it does nothing and silently produces no build.)

### CI workflows (`.github/workflows/`)
- **`release.yml`** — on a `v*` tag push (or manual dispatch with `publish=true`):
  `npm ci` → build NSIS installer + portable (real toolchain) → run the
  install/update/uninstall smoke test → publish the four assets to **this repo's
  own Releases**. This is the **only** workflow currently deployed in
  `att-desktop-releases`.
- **`smoke-test.yml`** — same build + smoke test, no publish; a pre-tag validation
  workflow that exists in this `desktop/` folder but is **NOT yet in the releases
  repo** (the connector token can't push workflow files — add it via the GitHub
  web UI before relying on it).

### The smoke test (`scripts/ci-smoke-test.js`)
Runs on the same Windows runner after building and proves the update pipeline
end-to-end automatically: silently installs the built `setup.exe`, asserts the
app exe **and** the uninstaller exist and the version registered correctly;
builds the next patch version and installs it **over** the first (a simulated
auto-update) asserting a clean in-place replace; then runs the uninstaller and
asserts a clean removal. This catches the exact "old removed, new not installed"
class that cannot be tested in the Linux sandbox.

## Local dev build (optional)
```bash
cd desktop
npm install
npm run build:win            # portable exe -> dist/A-Traders-Tool-<version>-portable.exe
npm run build:win:installer  # NSIS installer -> dist/A-Traders-Tool-<version>-setup.exe
```
electron-builder >= 26 embeds the exe FILE icon (build/icon.ico) via pure-JS
resedit even on Linux. Do not re-add `signAndEditExecutable: false` — that ships
the generic Electron icon on the exe file. To build the NSIS target *inside the
Replit sandbox* only (never for a release): after `npm install`, run
`node scripts/patch-nsis-uninstaller-reader.js` once, then build with
`NSIS_UNINSTALLER_READER=1 npm run build:win:installer`.

⚠️ **`build/icon.ico` must exist before building.** Only the .ico is kept in git;
if it's missing (fresh clone) regenerate it or the exe ships the generic icon:
`magick assets/icon.png -define icon:auto-resize=256,128,64,48,32,16 build/icon.ico`

## Source repo & CI
Auto-update uses **GitHub Releases** via electron-updater. The feed points at the
public repo **github.com/arturbarbaneagra/att-desktop-releases** (`build.publish`
in `package.json` — bakes the feed URL into the built app). **That same repo is
the source repo, the CI host, AND the releases feed**: its `release.yml` does
`actions/checkout@v4` of itself, builds, and publishes the assets to its own
Releases using the built-in `GITHUB_TOKEN` — **no Personal Access Token /
`RELEASES_TOKEN` secret is needed** (an earlier two-repo design used one; it's
gone).

> ⚠️ A stale `att-desktop` repo survives from that abandoned two-repo layout. It
> has **no workflows and has never built** (0 Actions runs). **Do NOT tag it** —
> that is exactly why `v1.2.0` was tagged there and silently never shipped while
> the app sat on `v1.1.9`. All shipping happens on **`att-desktop-releases`**.

## Shipping a new version
1. Make changes here in `desktop/` (the source of truth), bump `"version"` in
   `package.json` **and** the two root `"version"` fields in `package-lock.json`
   to match (else `npm ci` on the runner can fail). Do NOT regenerate the
   lockfile inside the Replit sandbox — it rewrites every `resolved` URL to
   Replit's internal proxy and breaks `npm ci`. Easiest: reuse the releases
   repo's existing lockfile and only string-replace the version — match ONLY
   `"version": "<old>"` and expect **exactly 2** hits (top-level + `packages[""]`);
   abort if not 2, since a dependency can coincidentally share the old version
   string and a blind global replace would corrupt its pin.
2. Sync this folder to **`att-desktop-releases`** (copy the tracked files;
   `node_modules/`/`dist/` are gitignored). When syncing via the Replit GitHub
   connector, build the tree with `base_tree` = the repo's current tree so the
   existing `.github/workflows/*` is inherited untouched (the connector token
   can't write workflow paths, but base_tree inheritance is fine).
3. Push a tag `v<version>` (e.g. `v1.2.1`) to **`att-desktop-releases`**. CI
   builds, smoke tests, and publishes `setup.exe`, `setup.exe.blockmap`,
   `latest.yml`, and `portable.exe` to that repo's own Releases.
4. Installed apps pick up `latest.yml` on next launch or within ~4 hours,
   download the FULL (hash-verified) installer, and install it on next quit. If
   an update ever fails, the app now shows a dismissible in-window bar linking to
   the releases page for a one-click manual re-download.

Advanced: an already-shipped build can be repointed without rebuilding by adding
an `"updateFeed"` object to the app's `settings.json`
(`%APPDATA%/A Trader's Tool/settings.json`), e.g.
`{"updateFeed": {"provider": "github", "owner": "me", "repo": "att-releases"}}`.

Advanced: an already-shipped build can be repointed without rebuilding by
adding an `"updateFeed"` object to the app's `settings.json`
(`%APPDATA%/A Trader's Tool/settings.json`), e.g.
`{"updateFeed": {"provider": "github", "owner": "me", "repo": "att-releases"}}`.

`node_modules/` and `dist/` are gitignored — this folder is excluded from the
Python Reserved-VM deployment and touches nothing in main.py / panel.html.
