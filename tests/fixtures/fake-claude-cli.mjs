#!/usr/bin/env node
// Fake `claude` CLI for the install tests: logs each call, and keeps the registered MCP servers in a file.
import { appendFileSync, readFileSync, writeFileSync, existsSync } from "node:fs";
const args = process.argv.slice(2);
const log = process.env.FAKE_CLI_LOG;
const store = `${log}.servers.json`;
appendFileSync(log, JSON.stringify(args) + "\n");
const servers = existsSync(store) ? JSON.parse(readFileSync(store, "utf8")) : {};
const [, verb, ...rest] = args;
if (verb === "get") {
  const s = servers[rest[0]];
  if (!s) { console.error(`No MCP server found with name: ${rest[0]}`); process.exit(1); }
  console.log(`${rest[0]}:\n  Args: ${s.join(" ")}`);
} else if (verb === "add") {
  const name = rest[rest.indexOf("--") - 1];
  servers[name] = rest.slice(rest.indexOf("--") + 1);
  writeFileSync(store, JSON.stringify(servers));
} else if (verb === "remove") {
  delete servers[rest[0]];
  writeFileSync(store, JSON.stringify(servers));
}
