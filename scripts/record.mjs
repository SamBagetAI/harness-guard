#!/usr/bin/env node
/**
 * Re-records the README's pictures from the examples, never your own harness:
 *
 *   npm run record
 *
 * - docs/demo.gif: `harness-guard` on the example harness, then on a skill that steals an SSH key.
 * - docs/social-preview.png: the 1280×640 card for GitHub (Settings → General → Social preview),
 *   checked to sit inside GitHub's 80px border.
 *
 * It copies the examples into a throwaway home, runs the real CLI there (static analysis only),
 * plays its output in a terminal drawn in your installed Google Chrome, and films it.
 * Needs `npm install` for the recording tools (dev dependencies only: Harness Guard itself has none).
 */
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import gifenc from "gifenc";
import { PNG } from "pngjs";
import { chromium } from "playwright-core";

const { GIFEncoder, quantize, applyPalette } = gifenc;
const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const W = 960;
const H = 540;
const FPS = 10;

/** The two commands and what the CLI really prints, run on a copy of the examples in a fake home. */
function runExamples() {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "hg-record-")));
  try {
    cpSync(join(repo, "examples/harness/home"), home, { recursive: true });
    cpSync(join(repo, "examples/harness/project"), join(home, "my-app"), { recursive: true });
    cpSync(join(repo, "examples/skills/notes-sync"), join(home, "downloads/notes-sync"), { recursive: true });
    const env = { ...process.env, HOME: home, HARNESS_GUARD_HOME: join(home, ".harness-guard"), HARNESS_GUARD_JUDGE: "off", NO_COLOR: "1" };
    const run = (args) => {
      const r = spawnSync(process.execPath, [join(repo, "harness-guard.mjs"), ...args, "--no-judge"], { cwd: join(home, "my-app"), env, encoding: "utf8" });
      if (r.status === 64 || r.error) throw new Error(`harness-guard ${args.join(" ")} failed: ${r.stderr || r.error}`);
      return r.stdout.replaceAll(home, "~").trimEnd();
    };
    return [
      { command: "harness-guard", output: run([]) },
      { command: "harness-guard ~/downloads/notes-sync", output: run([join(home, "downloads/notes-sync")]) },
    ];
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

/** A terminal that types each command, prints its output line by line, then sets window.done. */
function terminalPage(scenes) {
  return `<!doctype html><meta charset="utf-8"><style>
  body { margin: 0; width: ${W}px; height: ${H}px; background: #fbf8f2; font-family: Menlo, "SF Mono", monospace; }
  .win { position: absolute; inset: 14px; border-radius: 10px; background: #1d1b18; box-shadow: 0 6px 20px #0002; overflow: hidden; }
  .bar { height: 28px; display: flex; gap: 8px; align-items: center; padding: 0 12px; }
  .screen { position: absolute; top: 34px; left: 18px; right: 18px; bottom: 14px; overflow: hidden; display: flex; flex-direction: column; justify-content: flex-end; }
  .bar i { width: 12px; height: 12px; border-radius: 50%; background: #4a4640; }
  #out { color: #ece6da; font-size: 12.5px; line-height: 18px; white-space: pre-wrap; }
  .p { color: #f2c979; } .h { color: #fff; font-weight: bold; } .dim { color: #8c857a; }
  .bad { color: #ff6b5e; font-weight: bold; } .warn { color: #f2c979; font-weight: bold; } .ok { color: #7bd88f; font-weight: bold; }
  .cur { display: inline-block; width: 8px; height: 15px; background: #ece6da; vertical-align: -3px; }
</style><div class="win"><div class="bar"><i></i><i></i><i></i></div><div class="screen"><div id="out"></div></div></div>
<script>
const scenes = ${JSON.stringify(scenes)};
const out = document.getElementById("out");
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
const paint = (line) => {
  let s = esc(line)
    .replace(/(BLOCKED)/g, '<span class="bad">$1</span>')
    .replace(/(NEEDS REVIEW)/g, '<span class="warn">$1</span>')
    .replace(/^(✅ OK)/, '<span class="ok">$1</span>')
    .replace(/(   · .*)$/, '<span class="dim">$1</span>');
  return /^[A-Z]/.test(line) ? '<span class="h">' + s + "</span>" : s;
};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  for (const [i, scene] of scenes.entries()) {
    out.innerHTML = "";
    const prompt = document.createElement("div");
    prompt.innerHTML = '<span class="p">~/my-app $</span> <span id="cmd"></span><span class="cur"></span>';
    out.append(prompt);
    await wait(500);
    for (const ch of scene.command) { document.getElementById("cmd").textContent += ch; await wait(55); }
    await wait(350);
    prompt.querySelector(".cur").remove();
    prompt.querySelector("#cmd").removeAttribute("id");
    // A pause once the summary ("What this … can do") is on screen, before the details push it up.
    let summary = false;
    for (const line of scene.output.split("\\n")) {
      const d = document.createElement("div");
      d.innerHTML = paint(line) || " ";
      out.append(d);
      if (line.startsWith("What this")) summary = true;
      if (summary && !line) { summary = null; await wait(2500); }
      await wait(45);
    }
    await wait(i === scenes.length - 1 ? 4000 : 3500);
  }
  window.done = true;
})();
</script>`;
}

/** A 2× screenshot as W×H RGBA, each pixel the average of four: sharper text than a 1× capture. */
function halve(png) {
  const src = PNG.sync.read(png);
  const out = new Uint8Array(W * H * 4);
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      for (let c = 0; c < 4; c++) {
        const at = (yy, xx) => src.data[((y * 2 + yy) * src.width + x * 2 + xx) * 4 + c];
        out[(y * W + x) * 4 + c] = (at(0, 0) + at(0, 1) + at(1, 0) + at(1, 1)) >> 2;
      }
    }
  }
  return out;
}

async function recordDemo(browser, scenes) {
  const page = await browser.newPage({ viewport: { width: W, height: H }, deviceScaleFactor: 2 });
  // Each frame keeps when it was taken, so the GIF plays at the speed the terminal really moved.
  const frames = [];
  await page.setContent(terminalPage(scenes));
  while (!(await page.evaluate(() => window.done))) {
    const t = Date.now();
    frames.push({ png: await page.screenshot(), at: t });
    const left = 1000 / FPS - (Date.now() - t);
    if (left > 0) await page.waitForTimeout(left);
  }
  await page.close();

  const pixels = frames.map((f) => halve(f.png));
  const delays = frames.map((f, i) => (frames[i + 1] ? frames[i + 1].at - f.at : 1000 / FPS));
  // One palette for every frame, from the two full screens and the end, so colors don't flicker.
  const sample = new Uint8Array(W * H * 4 * 3);
  [pixels.length >> 1, (pixels.length * 3) >> 2, pixels.length - 1].forEach((k, i) => sample.set(pixels[k], i * W * H * 4));
  const palette = quantize(sample, 127);
  // A frame keeps only the pixels that changed; the rest are see-through and show the frame before.
  const CLEAR = palette.length;
  palette.push([255, 0, 255]);
  const gif = GIFEncoder();
  let previous = null;
  for (const [i, p] of pixels.entries()) {
    const index = applyPalette(p, palette.slice(0, CLEAR));
    const frame = previous ? index.map((v, j) => (v === previous[j] ? CLEAR : v)) : index;
    gif.writeFrame(frame, W, H, { palette: previous ? null : palette, delay: delays[i], transparent: !!previous, transparentIndex: CLEAR, dispose: 1 });
    previous = index;
  }
  gif.finish();
  writeFileSync(join(repo, "docs/demo.gif"), gif.bytes());
  return frames.length;
}

async function renderCard(browser) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 640 } });
  await page.goto(pathToFileURL(join(repo, "scripts/social.html")).href, { waitUntil: "load" });
  const outside = await page.evaluate(() =>
    [...document.querySelectorAll(".safe *")]
      .map((e) => [e.className || e.tagName, e.getBoundingClientRect()])
      .filter(([, r]) => r.left < 80 || r.top < 80 || r.right > 1200 || r.bottom > 560)
      .map(([name]) => name),
  );
  if (outside.length) throw new Error(`the social card crosses GitHub's 80px border: ${outside.join(", ")}`);
  await page.screenshot({ path: join(repo, "docs/social-preview.png") });
  await page.close();
}

const scenes = runExamples();
const browser = await chromium.launch({ channel: "chrome" }).catch((e) => {
  throw new Error(`could not start Google Chrome (playwright-core uses the installed one): ${e.message}`);
});
try {
  const n = await recordDemo(browser, scenes);
  await renderCard(browser);
  console.log(`docs/demo.gif (${n} frames) and docs/social-preview.png written`);
} finally {
  await browser.close();
}
