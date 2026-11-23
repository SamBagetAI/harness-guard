// harness-guard install and uninstall: the hooks in the user's settings, and the MCP server.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { CLI } from "./helpers.mjs";

const FAKE_CLI = fileURLToPath(new URL("./fixtures/fake-claude-cli.mjs", import.meta.url));

function setup(existing) {
  const dir = mkdtempSync(join(tmpdir(), "hg-install-"));
  const config = join(dir, ".claude");
  mkdirSync(config, { recursive: true });
  if (existing) writeFileSync(join(config, "settings.json"), JSON.stringify(existing, null, 2));
  const log = join(dir, "cli.log");
  const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env: { ...process.env, CLAUDE_CONFIG_DIR: config, HARNESS_GUARD_CLAUDE_BIN: FAKE_CLI, FAKE_CLI_LOG: log } });
  const settings = () => JSON.parse(readFileSync(join(config, "settings.json"), "utf8"));
  const calls = () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []);
  return { config, run, settings, calls };
}

const other = { matcher: "Bash", hooks: [{ type: "command", command: "my-own-hook" }] };

test("install adds the three hooks and the MCP server, keeps everything else", () => {
  const t = setup({ model: "opus", hooks: { PreToolUse: [other] } });
  const res = t.run("install");
  assert.equal(res.status, 0, res.stdout + res.stderr);
  const s = t.settings();
  assert.equal(s.model, "opus");
  assert.deepEqual(Object.keys(s.hooks).sort(), ["PostToolUse", "PreToolUse", "SessionStart"]);
  assert.deepEqual(s.hooks.PreToolUse[0], other, "the person's own hook stays first");
  assert.equal(s.hooks.PreToolUse[1].matcher, "Skill");
  assert.ok(existsSync(join(t.config, "settings.json.before-harness-guard")));
  assert.ok(t.calls().some((c) => c[1] === "add" && c.includes("harness-guard") && c.at(-1) === "mcp"));
});

test("install twice changes nothing the second time", () => {
  const t = setup({});
  t.run("install");
  const first = t.settings();
  const res = t.run("install");
  assert.match(res.stdout, /Hooks already up to date/);
  assert.match(res.stdout, /already registered/);
  assert.deepEqual(t.settings(), first);
  assert.equal(t.calls().filter((c) => c[1] === "add").length, 1);
});

test("install --dry-run changes nothing", () => {
  const t = setup({ model: "opus" });
  const res = t.run("install", "--dry-run");
  assert.match(res.stdout, /would be added/);
  assert.deepEqual(t.settings(), { model: "opus" });
  assert.ok(!t.calls().some((c) => c[1] === "add"));
});

test("uninstall takes out only what install put in", () => {
  const t = setup({ hooks: { PreToolUse: [other] } });
  t.run("install");
  const res = t.run("uninstall");
  assert.equal(res.status, 0, res.stdout);
  assert.deepEqual(t.settings().hooks, { PreToolUse: [other] });
  assert.ok(t.calls().some((c) => c[1] === "remove" && c[2] === "harness-guard"));
});

test("install refuses to touch a settings file that is not valid JSON", () => {
  const t = setup();
  writeFileSync(join(t.config, "settings.json"), "{ not json");
  const res = t.run("install");
  assert.equal(res.status, 64);
  assert.equal(readFileSync(join(t.config, "settings.json"), "utf8"), "{ not json");
});

test("without the claude CLI, install still adds the hooks and prints the MCP command", () => {
  const t = setup({});
  const res = spawnSync(process.execPath, [CLI, "install"], { encoding: "utf8", env: { ...process.env, CLAUDE_CONFIG_DIR: t.config, HARNESS_GUARD_CLAUDE_BIN: "/nowhere/claude" } });
  assert.equal(res.status, 1);
  assert.match(res.stdout, /claude mcp add --transport stdio --scope user harness-guard --/);
  assert.ok(t.settings().hooks.SessionStart);
});
