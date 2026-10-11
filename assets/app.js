/* Prism — in-browser IPA tweak injector.
 *
 * Everything runs on your device: the IPA never leaves the page. We open the .ipa (a zip), find the
 * app's main Mach-O binary, weak-link the tweak dylib into it, drop the dylib into the app's
 * Frameworks/ folder, and hand the repacked IPA back. No account, no Plus, no server — every feature
 * is on for everyone. The result is UNSIGNED: sign it with your own certificate (Sideloadly, Feather,
 * AltStore, ...) before it installs.
 *
 * The Mach-O edit is a port of spoti.pw's scripts/insert-dylib.py: an LC_LOAD_WEAK_DYLIB goes into
 * the free space Xcode leaves between the load commands and the first section. FAT binaries are
 * handled slice by slice.
 */

const LC_LOAD_DYLIB = 0x0c, LC_LOAD_WEAK_DYLIB = 0x80000018, LC_REEXPORT_DYLIB = 0x1f;
const LC_SEGMENT_64 = 0x19;
const MH_MAGIC_64 = 0xfeedfacf;      // thin 64-bit, little-endian
const FAT_MAGIC = 0xcafebabe, FAT_MAGIC_64 = 0xcafebabf;   // multi-arch, big-endian on disk

const log = (msg, cls = "") => {
  const el = document.getElementById("log");
  const line = document.createElement("div");
  line.className = "line " + cls;
  line.textContent = msg;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
};

/* ---- Mach-O: inject one weak dylib into a thin slice at byte `base`. Returns true if written. ---- */
function injectThin(bytes, base, installName) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset);
  const magic = dv.getUint32(base, true);
  if (magic !== MH_MAGIC_64) return false;          // only 64-bit; 32-bit Spotify is long gone

  const ncmds = dv.getUint32(base + 16, true);
  const sizeofcmds = dv.getUint32(base + 20, true);
  const nameBytes = new TextEncoder().encode(installName);

  let off = base + 32;
  let firstSection = Infinity;
  for (let i = 0; i < ncmds; i++) {
    const cmd = dv.getUint32(off, true);
    const cmdsize = dv.getUint32(off + 4, true);
    if (cmd === LC_LOAD_DYLIB || cmd === LC_LOAD_WEAK_DYLIB || cmd === LC_REEXPORT_DYLIB) {
      // name sits at off+24; compare up to the first NUL
      let end = off + 24;
      while (end < off + cmdsize && bytes[end] !== 0) end++;
      const existing = new TextDecoder().decode(bytes.subarray(off + 24, end));
      if (existing === installName) { log("    already weak-linked, skipping", "muted"); return true; }
    }
    if (cmd === LC_SEGMENT_64) {
      const nsects = dv.getUint32(off + 64, true);
      for (let s = 0; s < nsects; s++) {
        const sectOff = dv.getUint32(off + 72 + s * 80 + 48, true);
        if (sectOff) firstSection = Math.min(firstSection, base + sectOff);
      }
    }
    off += cmdsize;
  }

  const cmdsize = (24 + nameBytes.length + 1 + 7) & ~7;   // 24-byte header + NUL-terminated name, 8-aligned
  const end = base + 32 + sizeofcmds;
  if (end + cmdsize > firstSection) throw new Error("no room for another load command in this binary");
  for (let i = end; i < end + cmdsize; i++) if (bytes[i] !== 0) throw new Error("load-command free space is not empty");

  dv.setUint32(end, LC_LOAD_WEAK_DYLIB, true);
  dv.setUint32(end + 4, cmdsize, true);
  dv.setUint32(end + 8, 24, true);          // name offset within the command
  dv.setUint32(end + 12, 2, true);          // timestamp
  dv.setUint32(end + 16, 0x10000, true);    // current version 1.0.0
  dv.setUint32(end + 20, 0x10000, true);    // compat version 1.0.0
  bytes.set(nameBytes, end + 24);
  dv.setUint32(base + 16, ncmds + 1, true);
  dv.setUint32(base + 20, sizeofcmds + cmdsize, true);
  return true;
}

/* Patch every 64-bit slice (thin, or each arch of a FAT binary). */
function injectBinary(bytes, installName) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset);
  const head = dv.getUint32(0, true);
  const headBE = dv.getUint32(0, false);

  if (head === MH_MAGIC_64) {
    if (!injectThin(bytes, 0, installName)) throw new Error("not a 64-bit Mach-O");
    log("    patched thin arm64 binary", "ok");
    return;
  }
  if (headBE === FAT_MAGIC || headBE === FAT_MAGIC_64) {
    const narch = dv.getUint32(4, false);
    const wide = headBE === FAT_MAGIC_64;
    let patched = 0;
    for (let i = 0; i < narch; i++) {
      const rec = 8 + i * (wide ? 32 : 20);
      const offset = wide ? Number(dv.getBigUint64(rec + 8, false)) : dv.getUint32(rec + 8, false);
      if (dv.getUint32(offset, true) === MH_MAGIC_64) { injectThin(bytes, offset, installName); patched++; }
    }
    if (!patched) throw new Error("FAT binary has no 64-bit slice");
    log(`    patched ${patched} arch slice(s) of a FAT binary`, "ok");
    return;
  }
  throw new Error("unrecognised binary (decrypted, 64-bit IPA required)");
}

/* ---- find Payload/<App>.app and its main executable inside the opened zip ---- */
function findApp(zip) {
  const appDirs = new Set();
  zip.forEach((p) => { const m = p.match(/^Payload\/([^/]+\.app)\//); if (m) appDirs.add(m[1]); });
  if (appDirs.size === 0) throw new Error("no Payload/*.app in this IPA");
  const app = [...appDirs][0];
  const name = app.replace(/\.app$/, "");
  // The main binary is conventionally Payload/Name.app/Name.
  const execPath = `Payload/${app}/${name}`;
  if (!zip.file(execPath)) throw new Error(`main binary ${name} not found in ${app}`);
  return { app, name, execPath, frameworks: `Payload/${app}/Frameworks` };
}

/* ---- orchestration ---- */
let ipaFile = null;
const selectedTweaks = new Map();   // display name -> {url?|file?, dylibName}

async function run() {
  const out = document.getElementById("log");
  out.innerHTML = "";
  if (!ipaFile) { log("drop a decrypted Spotify .ipa first", "err"); return; }
  if (selectedTweaks.size === 0) { log("pick at least one tweak to inject", "err"); return; }

  try {
    document.getElementById("go").disabled = true;
    log(`opening ${ipaFile.name} (${(ipaFile.size / 1048576).toFixed(1)} MB)…`);
    const zip = await JSZip.loadAsync(ipaFile);
    const { name, execPath, frameworks } = findApp(zip);
    log(`app: ${name}`, "ok");

    const binary = new Uint8Array(await zip.file(execPath).async("arraybuffer"));
    for (const [label, t] of selectedTweaks) {
      log(`injecting ${label}…`);
      const dylibBytes = t.file
        ? new Uint8Array(await t.file.arrayBuffer())
        : new Uint8Array(await (await fetch(t.url)).arrayBuffer());
      const install = `@executable_path/Frameworks/${t.dylibName}`;
      injectBinary(binary, install);
      zip.file(`${frameworks}/${t.dylibName}`, dylibBytes);
      log(`    added Frameworks/${t.dylibName}`, "ok");
    }
    zip.file(execPath, binary);

    log("repacking…");
    const blob = await zip.generateAsync(
      { type: "blob", compression: "DEFLATE", compressionOptions: { level: 6 } },
      (m) => { if (m.percent) document.getElementById("bar").style.width = m.percent + "%"; }
    );
    const url = URL.createObjectURL(blob);
    const a = document.getElementById("download");
    a.href = url;
    a.download = ipaFile.name.replace(/\.ipa$/i, "") + "-prism.ipa";
    a.style.display = "inline-flex";
    log("done. the IPA is UNSIGNED — sign it with your own certificate before installing.", "ok");
  } catch (e) {
    log("error: " + e.message, "err");
  } finally {
    document.getElementById("go").disabled = false;
  }
}

/* ---- bundled tweaks + wiring ---- */
const BUNDLED = [
  { label: "spoti.pw — Liquid Glass", url: "tweaks/spotifyglass.dylib", dylibName: "spotifyglass.dylib",
    note: "Also drop in the AppGroups dylib below; the full kit (plugins, Info.plist) needs the spoti.pw build pipeline." },
  { label: "spoti.pw — App Groups (dependency)", url: "tweaks/SpotifyGlassAppGroups.dylib", dylibName: "SpotifyGlassAppGroups.dylib" },
  { label: "AutoFlex", url: "tweaks/autoflex.dylib", dylibName: "autoflex.dylib" },
];

function buildTweakList() {
  const list = document.getElementById("tweaks");
  BUNDLED.forEach((t) => {
    const row = document.createElement("label");
    row.className = "tweak";
    row.innerHTML =
      `<input type="checkbox"><span class="t-name">${t.label}</span>` +
      (t.note ? `<span class="t-note">${t.note}</span>` : "");
    row.querySelector("input").addEventListener("change", (e) => {
      if (e.target.checked) selectedTweaks.set(t.label, { url: t.url, dylibName: t.dylibName });
      else selectedTweaks.delete(t.label);
    });
    list.appendChild(row);
  });
}

function wireDrop() {
  const drop = document.getElementById("drop");
  const pick = document.getElementById("ipa");
  const setFile = (f) => {
    if (!f) return;
    ipaFile = f;
    drop.querySelector(".hint").textContent = `${f.name} — ${(f.size / 1048576).toFixed(1)} MB`;
    drop.classList.add("has");
  };
  drop.addEventListener("click", () => pick.click());
  pick.addEventListener("change", (e) => setFile(e.target.files[0]));
  ["dragover", "dragenter"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => setFile(e.dataTransfer.files[0]));

  const custom = document.getElementById("custom");
  custom.addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (!f) return;
    selectedTweaks.set("custom: " + f.name, { file: f, dylibName: f.name });
    log(`custom dylib queued: ${f.name}`, "ok");
  });
}

document.addEventListener("DOMContentLoaded", () => {
  buildTweakList();
  wireDrop();
  document.getElementById("go").addEventListener("click", run);
});
