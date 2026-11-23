// Every example in examples/ gives the verdict written in examples/expected.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

test("every example gives its expected verdict", () => {
  const script = fileURLToPath(new URL("../examples/check.mjs", import.meta.url));
  const res = spawnSync(process.execPath, [script], { encoding: "utf8", env: { ...process.env, HARNESS_GUARD_JUDGE: "off" } });
  assert.equal(res.status, 0, res.stdout + res.stderr);
});
