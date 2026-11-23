#!/usr/bin/env node
// Faux CLI claude pour les tests : renvoie la réponse posée dans FAKE_JUDGE et compte les appels.
import { appendFileSync } from "node:fs";
let input = "";
for await (const c of process.stdin) input += c;
if (process.env.FAKE_CALLS) appendFileSync(process.env.FAKE_CALLS, "x");
if (process.env.FAKE_FAIL) { console.log(JSON.stringify({ is_error: true, result: "panne simulée" })); process.exit(1); }
console.log(JSON.stringify({ is_error: false, structured_output: JSON.parse(process.env.FAKE_JUDGE) }));
