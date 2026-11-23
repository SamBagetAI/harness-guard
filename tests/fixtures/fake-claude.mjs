#!/usr/bin/env node
// Fake claude CLI for the tests: returns the answer set in FAKE_JUDGE and counts the calls.
import { appendFileSync } from "node:fs";
let input = "";
for await (const c of process.stdin) input += c;
if (process.env.FAKE_CALLS) appendFileSync(process.env.FAKE_CALLS, "x");
if (process.env.FAKE_INPUT) appendFileSync(process.env.FAKE_INPUT, input);
if (process.env.FAKE_FAIL) { console.log(JSON.stringify({ is_error: true, result: "simulated failure" })); process.exit(1); }
console.log(JSON.stringify({ is_error: false, structured_output: JSON.parse(process.env.FAKE_JUDGE) }));
