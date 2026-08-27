/* Run the conformance vectors through the JavaScript verifier.
 *
 *   node packages/js/run-conformance.mjs                 # local vectors
 *   node packages/js/run-conformance.mjs --published     # over HTTP, as an outsider
 *
 * This is the point of having a second implementation. A disagreement here is
 * the most useful output this repository can produce, and it does not say which
 * side is wrong -- `CONTRIBUTING.md` is explicit that it may well be the Python
 * one. So a mismatch prints both verdicts and the rule the vector pins, and
 * exits non-zero without editorialising about whose fault it is.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { IMPLEMENTATION, verifyEvent } from "./lineageauth.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const LOCAL = join(HERE, "..", "..", "conformance");
const PUBLISHED = "https://miyawakiclaude.github.io/lineageauth/conformance";

const published = process.argv.includes("--published");

async function load(relative) {
  if (published) {
    const response = await fetch(`${PUBLISHED}/${relative}`);
    if (!response.ok) throw new Error(`${relative}: HTTP ${response.status}`);
    return response.json();
  }
  return JSON.parse(await readFile(join(LOCAL, relative), "utf8"));
}

function pad(text, width) {
  return String(text).padEnd(width);
}

const manifest = await load("manifest.json");

console.log(`${IMPLEMENTATION.name} against ${published ? PUBLISHED : "conformance/"}`);
console.log(`${manifest.vectors.length} vector(s)\n`);

let agreed = 0;
const disagreements = [];

for (const entry of manifest.vectors) {
  const documents = await load(entry.file);
  const expectVerify = entry.expect === "must-verify";

  let reachedVerify = true;
  const details = [];
  for (const document of documents) {
    let result;
    try {
      result = await verifyEvent(document);
    } catch (error) {
      result = { ok: false, reason: "THREW", detail: error.message };
    }
    if (!result.ok) {
      reachedVerify = false;
      details.push(`${result.reason}: ${result.detail}`);
    }
  }

  const matches = reachedVerify === expectVerify;
  if (matches) agreed += 1;
  else disagreements.push({ entry, reachedVerify, details });

  console.log(
    `  ${matches ? "agree " : "DIFFER"}  ${pad(entry.name, 34)} ` +
      `expect=${pad(entry.expect, 12)} reached=${reachedVerify ? "verify" : "refuse"}`
  );
}

console.log(`\n${agreed}/${manifest.vectors.length} vectors agree with the package`);

if (disagreements.length > 0) {
  console.log("\nDisagreements. Which side is wrong is an open question:\n");
  for (const { entry, reachedVerify, details } of disagreements) {
    console.log(`  ${entry.name}`);
    console.log(`    the package says : ${entry.expect}`);
    console.log(`    this verifier    : ${reachedVerify ? "must-verify" : "must-refuse"}`);
    console.log(`    rule             : ${entry.rule}`);
    if (details.length) console.log(`    why              : ${details.join(" | ")}`);
    console.log("");
  }
  console.log(
    "Open an issue. CONTRIBUTING.md says the reference implementation may be the\n" +
      "one that is wrong, and a disagreement is worth more than another passing test."
  );
  process.exit(1);
}

process.exit(0);
