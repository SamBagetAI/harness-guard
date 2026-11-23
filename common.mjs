// Helpers shared by harness-guard.mjs, harness.mjs and judge.mjs: verdicts, the state folder,
// safe file reading, secret redaction, front matter, and a small concurrency helper.

import { readFileSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// ── Verdicts ─────────────────────────────────────────────────────────────

export const RANK = { ok: 0, info: 0, warn: 1, block: 2 };
export const VERDICTS = ["ok", "warn", "block"];
export const VERDICT_TEXT = { ok: "✅ OK", warn: "⚠️  NEEDS REVIEW", block: "⛔ BLOCKED" };
export const ICON = { ok: "✅", warn: "⚠️ ", block: "⛔", info: "·" };

/** The most serious level among findings (or anything with a `level`). */
export const worst = (items) => VERDICTS[Math.max(0, ...items.map((f) => RANK[f.level] ?? 0))];
/** A finding that still counts: not approved by the person, not cleared by the judge. */
export const live = (f) => !f.approved && !f.cleared;

export const list = (values, max = 6) => (values.length ? values.slice(0, max).join(", ") + (values.length > max ? `, … (+${values.length - max})` : "") : "—");

export function groupBy(items, keyOf) {
  const groups = new Map();
  for (const item of items) {
    const key = keyOf(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

// ── Paths and files ──────────────────────────────────────────────────────

/** The home folder the harness is read from (HARNESS_GUARD_USER_HOME lets tests use a fake one). */
export const userHome = () => process.env.HARNESS_GUARD_USER_HOME || homedir();
export const tilde = (p, home = userHome()) => (p && p.startsWith(home) ? `~${p.slice(home.length)}` : p);
/** A sub-folder of the state folder: approvals, the harness approval, the judge cache. */
export const stateDir = (sub) => join(process.env.HARNESS_GUARD_HOME || join(homedir(), ".harness-guard"), sub);

export const read = (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } };
/** The parsed file, null when it is missing, or { __invalid: true } when it is not valid JSON. */
export function readJson(p) {
  const t = read(p);
  if (t == null) return null;
  try { return JSON.parse(t); } catch { return { __invalid: true }; }
}
/** Marks a cache file as just used, so the purge keeps it. */
export const touch = (p) => { try { const now = new Date(); utimesSync(p, now, now); } catch {} };
/** Like readJson, but an invalid file counts as missing. */
export const readJsonOrNull = (p) => { const v = readJson(p); return v?.__invalid ? null : v; };

/** A field of a Markdown file's front matter (`name`, `description`…), or undefined. */
export function frontmatterField(text, key) {
  const fm = String(text).match(/^---\s*\n([\s\S]*?)\n---/)?.[1];
  return fm?.match(new RegExp(`^${key}:\\s*["']?([^"'\\n]+?)["']?\\s*$`, "m"))?.[1];
}

// ── Secrets ──────────────────────────────────────────────────────────────

/** Masks secrets slipped into a text: NAME_KEY=value, a password in a URL, recognisable tokens. */
export function redactText(t) {
  return String(t)
    .replace(/\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|CREDENTIALS?|AUTH)[A-Z0-9_]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'`;&|)]+)/g, "$1=<redacted>")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/[^:\s\/@]+:)[^@\s]+@/gi, "$1<redacted>@")
    .replace(/\b(sk-[\w-]{10,}|sk_(?:live|test)_\w{10,}|re_[A-Za-z0-9_]{10,}|ghp_\w{10,}|gho_\w{10,}|github_pat_\w{10,}|xox[abps]-[\w-]{10,}|AKIA[0-9A-Z]{12,}|AIza[\w-]{20,}|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,})/g, "<redacted>")
    .replace(/(--?(?:password|passwd|token|api-key|apikey|secret)[= ])("[^"]*"|'[^']*'|\S+)/gi, "$1<redacted>")
    .replace(/(\bBearer\s+)[\w.~+\/-]{12,}=*/g, "$1<redacted>");
}
export const hasSecret = (t) => redactText(t) !== String(t);

// ── Concurrency ──────────────────────────────────────────────────────────

/** Runs fn over items, at most n at a time, and returns the results in order. */
export async function mapLimit(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) { const k = next++; out[k] = await fn(items[k], k); }
  }));
  return out;
}
