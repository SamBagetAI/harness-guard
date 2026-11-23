#!/usr/bin/env node
// Runs every example and checks it gives the verdict written in expected.json.
// Static analysis only (no AI judge), in a throwaway state folder: nothing on your machine changes.
//
//   node examples/check.mjs

import { mkdtempSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
process.env.HARNESS_GUARD_JUDGE = "off";
process.env.HARNESS_GUARD_HOME = mkdtempSync(join(tmpdir(), "harness-guard-examples-"));
const { scan, approve } = await import("../harness-guard.mjs");
const { scanHarness } = await import("../harness.mjs");

const expected = JSON.parse(readFileSync(join(here, "expected.json"), "utf8"));
let failed = 0;
const line = (ok, name, got, want, why) => {
  if (!ok) failed++;
  console.log(`${ok ? "✓" : "✗"} ${name.padEnd(28)} ${got}${ok ? "" : ` (expected ${want})`}   ${why}`);
};

for (const [name, e] of Object.entries(expected.skills)) {
  const r = scan(join(here, "skills", name));
  line(r.verdict === e.verdict, name, r.verdict, e.verdict, e.why);
}

const rp = expected.rugPull;
approve(join(here, "skills", rp.approve));
const update = scan(join(here, "skills", rp.update));
const added = update.diff?.added?.net ?? [];
line(update.verdict === rp.verdict && rp.newNetwork.every((h) => added.includes(h)), `${rp.approve} → ${rp.update}`, `${update.verdict}, new: ${added.join(", ") || "—"}`, `${rp.verdict}, new: ${rp.newNetwork.join(", ")}`, rp.why);

const hx = expected.harness;
process.env.HARNESS_GUARD_USER_HOME = join(here, hx.home);
const h = await scanHarness({ cwd: join(here, hx.project), judge: "off", record: null });
line(h.verdict === hx.verdict, "harness", h.verdict, hx.verdict, hx.why);
for (const [key, want] of Object.entries(hx.pieces)) {
  const [kind, name] = [key.slice(0, key.indexOf(":")), key.slice(key.indexOf(":") + 1)];
  const p = h.pieces.find((x) => x.kind === kind && x.name === name);
  line(p?.verdict === want, `  ${key}`, p?.verdict ?? "missing", want, "");
}

console.log(failed ? `\n${failed} example(s) off.` : "\nEvery example gives its expected verdict.");
process.exitCode = failed ? 1 : 0;
