// Worker for warmScans: analyses a share of the skills so that their results are in the cache.
// It only reads files and writes the analysis cache, like the main thread would.
import { parentPort, workerData } from "node:worker_threads";

const { scan } = await import("./harness-guard.mjs");
for (const dir of workerData.dirs) {
  try { scan(dir, { record: null }); } catch {}
}
parentPort.postMessage("done");
