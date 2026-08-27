/* Canonicalize payloads read from stdin, one JSON value per line.
 *
 *   echo '{"b":1,"a":2}' | node packages/js/canonicalize.mjs
 *
 * Emits one JSON object per line: {"jcs": "...", "eventId": "sha256:..."} or
 * {"error": "..."}. Exists so the two implementations can be compared on the
 * thing that actually has to agree.
 *
 * The conformance vectors compare verdicts, which is a coarse signal: two
 * implementations can both say "verify" while disagreeing about the bytes they
 * verified, and that disagreement only surfaces later, as an event id nobody
 * can resolve. Comparing canonical output catches it at the point it happens.
 */

import { createInterface } from "node:readline";

import { eventId, jcs } from "./lineageauth.js";

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });

for await (const line of lines) {
  if (!line.trim()) continue;
  try {
    const value = JSON.parse(line);
    const canonical = jcs(value);
    const id = typeof value === "object" && value !== null && !Array.isArray(value)
      ? await eventId(value)
      : null;
    process.stdout.write(JSON.stringify({ jcs: canonical, eventId: id }) + "\n");
  } catch (error) {
    process.stdout.write(JSON.stringify({ error: String(error && error.message) }) + "\n");
  }
}
