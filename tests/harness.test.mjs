// The whole harness: hooks, MCP, settings, permissions, plugins, approval, secret redaction.
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { approve, hookResponse, scanHarness, approveHarness, redact, redactText, fakeHarness } from "./helpers.mjs";

test("harness: hooks, MCP, settings, plugins and commands are analysed", async () => {
  const { home, cwd } = fakeHarness();
  process.env.HARNESS_GUARD_USER_HOME = home;
  try {
    const h = await scanHarness({ cwd, judge: "off", record: null });
    const piece = (kind, name) => h.pieces.find((p) => p.kind === kind && p.name.includes(name));
    assert.equal(piece("hook", "UserPromptSubmit").verdict, "warn");
    assert.equal(piece("hook", "PostToolUse").verdict, "block", "the plugin script reads ~/.ssh and sends it");
    assert.equal(piece("mcp", "loose").verdict, "warn");
    assert.equal(piece("mcp", "pinned").verdict, "ok");
    assert.equal(piece("command", "go").verdict, "block");
    const settings = piece("setting", "user settings");
    assert.ok(settings.findings.some((f) => f.rule === "ai-proxy"));
    assert.deepEqual(settings.risky, ["Bash(curl:*)"]);
    assert.ok(!settings.text.includes("tok_1234"), "the token value is redacted");
    assert.equal(h.summary.aiTraffic.includes("llm-proxy.unknown.io"), true);
    assert.equal(h.verdict, "block");
  } finally { delete process.env.HARNESS_GUARD_USER_HOME; }
});

test("harness: after approve, only what changes is reported", async () => {
  const { home, cwd } = fakeHarness();
  process.env.HARNESS_GUARD_USER_HOME = home;
  try {
    await approveHarness({ cwd });
    const same = await scanHarness({ cwd, judge: "off" });
    assert.equal(same.verdict, "ok");
    const s = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8"));
    s.hooks.Stop = [{ hooks: [{ type: "command", command: "echo done" }] }];
    writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify(s));
    const after = await scanHarness({ cwd, judge: "off" });
    const stop = after.pieces.find((p) => p.name.startsWith("Stop"));
    assert.equal(stop.isNew, true);
    assert.equal(after.verdict, "warn");
  } finally { delete process.env.HARNESS_GUARD_USER_HOME; }
});

test("harness: secret redaction", () => {
  const r = redact({ env: { GITHUB_TOKEN: "abc", URL: "https://x.dev" }, headers: { Authorization: "Bearer zzz" }, other: "ghp_abcdefghijklmnopqrstu" });
  assert.equal(r.env.GITHUB_TOKEN, "<redacted>");
  assert.equal(r.env.URL, "https://x.dev");
  assert.equal(r.headers.Authorization, "<redacted>");
  assert.equal(r.other, "<redacted>");
});

test("SessionStart hook: warns when a piece is blocked", async () => {
  const { home, cwd } = fakeHarness();
  process.env.HARNESS_GUARD_USER_HOME = home;
  try {
    const res = await hookResponse({ hook_event_name: "SessionStart", cwd });
    assert.equal(res.hookSpecificOutput.hookEventName, "SessionStart");
    assert.match(res.hookSpecificOutput.additionalContext, /Blocked pieces/);
  } finally { delete process.env.HARNESS_GUARD_USER_HOME; }
});

test("harness: a secret slipped into an allow rule is reported and never shown or sent", async () => {
    const secret = "re_AbCdEf1234567890xyz";
  const pw = "S3cr3tPassw0rd";
  for (const t of [`Bash(RESEND_API_KEY=${secret} node send.js)`, `Bash(psql postgres://admin:${pw}@db.host/app)`, `Bash(curl -H "Authorization: Bearer abcdefghijklmnop123" x)`]) {
    const r = redactText(t);
    assert.ok(!r.includes(secret) && !r.includes(pw) && !r.includes("abcdefghijklmnop123"), r);
  }
  const { home, cwd } = fakeHarness();
  writeFileSync(join(home, ".claude", "settings.local.json"), JSON.stringify({ permissions: { allow: [`Bash(RESEND_API_KEY=${secret} node send.js)`, `Bash(psql postgres://admin:${pw}@db.host/app)`] } }));
  process.env.HARNESS_GUARD_USER_HOME = home;
  try {
    const h = await scanHarness({ cwd, judge: "off", record: null });
    const local = h.pieces.find((p) => p.name === "user settings, local");
    assert.equal(local.findings.filter((f) => f.rule === "secret-in-clear").length, 2);
    const all = JSON.stringify(h);
    assert.ok(!all.includes(secret) && !all.includes(pw), "no secret value in the report");
  } finally { delete process.env.HARNESS_GUARD_USER_HOME; }
});
