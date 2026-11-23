#!/usr/bin/env node
// Mesure skillcheck sur un corpus étiqueté.
// Usage : node bench/run.mjs <corpus> [--judge] [--out fichier.tsv]
// Le corpus contient manifest.json ([{id, label: "benign"|"malicious"}]) et <label>/<id>/.

import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { check } from "../skillcheck.mjs";

const args = process.argv.slice(2);
const corpus = resolve(args.find((a) => !a.startsWith("--")) ?? ".");
const useJudge = args.includes("--judge");
const out = args.includes("--out") ? args[args.indexOf("--out") + 1] : null;
if (!useJudge) process.env.SKILLCHECK_JUDGE = "off";

const manifest = JSON.parse(readFileSync(join(corpus, "manifest.json"), "utf8"));
const rows = new Array(manifest.length);
let next = 0, done = 0;
await Promise.all(Array.from({ length: useJudge ? 4 : 8 }, async () => {
  while (next < manifest.length) {
    const k = next++;
    const s = manifest[k];
    const r = await check(join(corpus, s.label, s.id), { judge: useJudge });
    const top = r.findings.find((f) => !f.approved && !f.cleared);
    rows[k] = { id: s.id, label: s.label, verdict: r.verdict, judge: r.judge?.verdict ?? (r.judgeError ? "error" : "-"), reason: top?.label ?? "", judgeError: (r.judgeError ?? "").replace(/\s+/g, " ") };
    if (++done % 20 === 0) process.stderr.write(`${done}/${manifest.length}\n`);
  }
}));

function metrics(positive) {
  const tp = rows.filter((r) => r.label === "malicious" && positive(r)).length;
  const fn = rows.filter((r) => r.label === "malicious" && !positive(r)).length;
  const fp = rows.filter((r) => r.label === "benign" && positive(r)).length;
  const tn = rows.filter((r) => r.label === "benign" && !positive(r)).length;
  const recall = tp / (tp + fn), precision = tp / (tp + fp || 1), fpr = fp / (fp + tn);
  const f1 = (2 * precision * recall) / (precision + recall || 1);
  return { tp, fn, fp, tn, recall, precision, fpr, f1 };
}
const pct = (x) => `${(100 * x).toFixed(1)} %`;
const show = (name, m) => console.log(`${name.padEnd(34)} attrapés ${m.tp}/${m.tp + m.fn} (${pct(m.recall)})   faux positifs ${m.fp}/${m.fp + m.tn} (${pct(m.fpr)})   précision ${pct(m.precision)}   F1 ${m.f1.toFixed(3)}`);

const n = (l) => rows.filter((r) => r.label === l).length;
console.log(`Corpus : ${n("malicious")} malveillants, ${n("benign")} sains · ${useJudge ? "statique + juge IA" : "statique seul"}\n`);
show("Bloqué (⛔)", metrics((r) => r.verdict === "block"));
show("Bloqué ou à vérifier (⛔ + ⚠️)", metrics((r) => r.verdict !== "ok"));
const errors = rows.filter((r) => r.judge === "error").length;
if (useJudge) console.log(`\nJuge : ${errors} erreur(s) sur ${rows.length}`);

console.log("\nMalveillants passés en ✅ :");
for (const r of rows.filter((r) => r.label === "malicious" && r.verdict === "ok")) console.log(`   ${r.id}`);
console.log("\nSains bloqués ⛔ :");
for (const r of rows.filter((r) => r.label === "benign" && r.verdict === "block")) console.log(`   ${r.id}   ${r.reason}`);
console.log("\nSains en ⚠️ :");
for (const r of rows.filter((r) => r.label === "benign" && r.verdict === "warn")) console.log(`   ${r.id}   ${r.reason}`);

if (out) {
  writeFileSync(out, ["id\tlabel\tverdict\tjudge\treason\tjudge_error", ...rows.map((r) => [r.id, r.label, r.verdict, r.judge, r.reason, r.judgeError].join("\t"))].join("\n") + "\n");
  console.error(`Résultats : ${out}`);
}
