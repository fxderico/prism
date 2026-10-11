# Prism

In-browser IPA tweak injector. Drop a **decrypted** Spotify `.ipa`, pick one or more tweak dylibs,
and Prism weak-links them into the app's main Mach-O binary and drops the dylibs into `Frameworks/`,
then hands the repacked IPA back. Everything runs on your device — the IPA never leaves the page.
No account, no Plus tier, no paywall: every feature is on for everyone.

## How it works

1. The `.ipa` is opened as a zip in the browser (JSZip).
2. `Payload/<App>.app/<App>` (the main binary) gets an `LC_LOAD_WEAK_DYLIB` command added in the free
   space Xcode leaves between the load commands and the first section — a JS port of spoti.pw's
   `scripts/insert-dylib.py`, extended to patch every slice of a FAT binary.
3. Each chosen dylib is written to `Payload/<App>.app/Frameworks/`, and the install name is
   `@executable_path/Frameworks/<name>.dylib` so no extra rpath is needed.
4. The zip is repacked and downloaded.

## Important

- The input must be a **decrypted**, 64-bit IPA.
- The output is **unsigned**. Sign it with your own certificate (Sideloadly, Feather, AltStore, …)
  before it will install on a device.
- Bundled tweaks are the spoti.pw dylibs and AutoFlex. The full spoti.pw kit (plugins, Info.plist
  edits, app intents) is more than a single dylib — use the spoti.pw build pipeline for that; Prism
  does the dylib weak-link.

## Deploy

Pushing to `main` builds and publishes via GitHub Pages (`.github/workflows/pages.yml`). Enable Pages
→ "GitHub Actions" in the repo settings once.
