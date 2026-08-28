/* A second implementation of LineageAuth verification, written to disagree.
 *
 * `CONTRIBUTING.md` asks for exactly one thing above all others: an independent
 * implementation that reaches a different verdict on the same events. Until
 * somebody's verifier has run the conformance vectors and either agreed or
 * found the first one wrong, "the specification is implementable" is an opinion
 * held by whoever wrote both sides.
 *
 * This is the second side. It is deliberately *not* a port.
 *
 * Independence is the whole value, so the awkward parts are re-derived from the
 * specification rather than translated:
 *
 *   - RFC 8785 canonicalization is implemented here. The Python side delegates
 *     it to a library precisely so it cannot be got subtly wrong, and this side
 *     writes it out precisely so a subtle mistake in either becomes visible.
 *     Two implementations that call the same library agree by construction and
 *     prove nothing.
 *   - base58btc decoding, the multicodec prefix check, the signing preimage and
 *     the event id are all re-derived from the documents.
 *
 * What is *not* re-derived: SHA-256 and Ed25519 come from WebCrypto. Those are
 * primitives with published test vectors and no interpretation to disagree
 * about, and hand-rolling a curve would be adding risk without adding evidence.
 *
 * Runs unchanged in a browser and in Node (>=18), because both expose the same
 * `crypto.subtle`. No dependencies, no build step.
 */

const PROTOCOL = "lineageauth";
const SUPPORTED_VERSIONS = new Set(["0.1"]);

/* b"lineageauth:event:v1\n" -- the domain separator, byte for byte. If this
 * string differs from the other implementation's by one character, every event
 * id differs and nothing interoperates. It is written out rather than derived
 * so that a diff is visible. */
const PREIMAGE_PREFIX = "lineageauth:event:v1\n";

const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Event types this verifier will give semantics to. An unregistered type is not
 * assumed harmless: docs/24 fails closed, so an unknown type is refused rather
 * than admitted with a shrug. */
const KNOWN_TYPES = new Set([
  "root.create", "recovery.policy", "delegation.grant", "delegation.revoke",
  "root.succession", "approval.receipt",
  "artifact.register", "artifact.receipt", "attestation.issue",
  "task.request", "task.claim", "task.release", "task.result", "task.verify",
  "task.cancel", "claim.coordinate", "work.receipt",
  "profile.statement", "skill.claim", "availability.statement",
  "fleet.create", "fleet.bind", "fleet.unbind",
  "dispute.open", "jury.disclose", "jury.vote",
  "artifact.reuse", "artifact.improve", "impact.attest",
]);

export class VerificationError extends Error {}

const subtle = (globalThis.crypto && globalThis.crypto.subtle) || null;

function requireSubtle() {
  if (!subtle) {
    throw new VerificationError(
      "no WebCrypto available; this verifier needs crypto.subtle for SHA-256 and Ed25519"
    );
  }
  return subtle;
}

/* ------------------------------------------------------------ RFC 8785 (JCS)
 *
 * Re-derived from the specification. The rules that actually bite:
 *
 *   - object keys sort by their UTF-16 code units, which is what JavaScript's
 *     default string comparison already does. Sorting by code *point* would
 *     differ for characters outside the BMP, and that is a real divergence
 *     rather than a theoretical one.
 *   - numbers use ECMAScript's Number::toString, with the sole exception that
 *     -0 serialises as 0.
 *   - strings escape only what JSON requires, using \\u00xx for other controls.
 *   - no whitespace anywhere.
 */

const ESCAPES = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

function canonicalString(value) {
  let out = '"';
  for (const ch of value) {
    const escape = ESCAPES[ch];
    if (escape !== undefined) {
      out += escape;
    } else if (ch < " ") {
      out += "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

function canonicalNumber(value) {
  if (!Number.isFinite(value)) {
    throw new VerificationError("a canonical payload cannot contain NaN or Infinity");
  }
  // RFC 8785 leans on ECMAScript number-to-string, with -0 written as 0.
  return Object.is(value, -0) ? "0" : String(value);
}

export function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return canonicalNumber(value);
  if (typeof value === "string") return canonicalString(value);
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(); // UTF-16 code unit order
    return "{" + keys.map((k) => canonicalString(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  throw new VerificationError(`cannot canonicalize a value of type ${typeof value}`);
}

/* ------------------------------------------------------------ encodings */

export function b64uDecode(text) {
  if (typeof text !== "string") throw new VerificationError("base64url value must be a string");
  if (text.includes("=")) {
    // Padding would give one signature two encodings, and one event two ids.
    throw new VerificationError("base64url value must not be padded");
  }
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new VerificationError("base64url value contains a character outside the alphabet");
  }
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);

  // Re-encoding must reproduce the input, or trailing bits were non-canonical.
  if (b64uEncode(bytes) !== text) {
    throw new VerificationError("base64url value is not canonically encoded");
  }
  return bytes;
}

export function b64uEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base58Decode(text) {
  if (typeof text !== "string" || text.length === 0) {
    throw new VerificationError("base58btc value must be a non-empty string");
  }
  const bytes = [0];
  for (const ch of text) {
    const index = BASE58_ALPHABET.indexOf(ch);
    if (index < 0) throw new VerificationError(`'${ch}' is not in the base58btc alphabet`);
    let carry = index;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading '1's are leading zero bytes.
  for (const ch of text) {
    if (ch !== "1") break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/* ------------------------------------------------------------ did:key */

export function publicKeyFromDidKey(did) {
  if (typeof did !== "string") throw new VerificationError("DID must be a string");
  if (!did.startsWith("did:key:")) {
    throw new VerificationError(`only did:key is supported, got ${did.slice(0, 24)}`);
  }
  const identifier = did.slice("did:key:".length);
  for (const separator of ["#", "?", "/", ";"]) {
    if (identifier.includes(separator)) {
      // A DID URL is not a signer identity: did:key:zAAA#zBBB must never be
      // treated as did:key:zAAA.
      throw new VerificationError(`DID URL syntax is not a signer identity (found '${separator}')`);
    }
  }
  if (!identifier.startsWith("z")) {
    throw new VerificationError("did:key identifier must be multibase base58btc ('z')");
  }
  const decoded = base58Decode(identifier.slice(1));
  if (decoded.length !== 34) {
    throw new VerificationError(`expected 34 bytes (2 multicodec + 32 key), got ${decoded.length}`);
  }
  if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    // An X25519 did:key is syntactically a did:key and is not a signing key.
    throw new VerificationError(
      `unsupported multicodec 0x${toHex(decoded.slice(0, 2))}; this protocol verifies Ed25519 only`
    );
  }
  return decoded.slice(2);
}

/* ------------------------------------------------------------ the event */

export function preimage(payload) {
  return new TextEncoder().encode(PREIMAGE_PREFIX + jcs(payload));
}

export async function eventId(payload) {
  const digest = await requireSubtle().digest("SHA-256", preimage(payload));
  return "sha256:" + toHex(new Uint8Array(digest));
}

async function verifyProof(payload, proof) {
  if (!proof || typeof proof !== "object") return { ok: false, reason: "proof is not an object" };
  if (proof.alg !== "Ed25519") {
    return { ok: false, reason: `unsupported algorithm ${JSON.stringify(proof.alg)}` };
  }
  let key;
  let signature;
  try {
    key = publicKeyFromDidKey(proof.signer);
    signature = b64uDecode(proof.sig);
  } catch (error) {
    return { ok: false, reason: error.message };
  }
  if (signature.length !== 64) {
    return { ok: false, reason: `an Ed25519 signature is 64 bytes, got ${signature.length}` };
  }
  const imported = await requireSubtle().importKey("raw", key, { name: "Ed25519" }, false, [
    "verify",
  ]);
  const ok = await requireSubtle().verify(
    { name: "Ed25519" },
    imported,
    signature,
    preimage(payload)
  );
  return { ok, reason: ok ? "signature verified" : "signature does not verify" };
}

/**
 * Verify one envelope's integrity.
 *
 * Returns a structured result rather than a boolean, for the same reason the
 * other implementation does: "did not verify" and "verified" are not the only
 * two things worth telling a caller.
 */
export async function verifyEvent(envelope) {
  const warnings = [];
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return { ok: false, reason: "MALFORMED", detail: "an envelope must be a JSON object" };
  }
  const { payload, proofs } = envelope;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, reason: "MALFORMED", detail: "payload must be a JSON object" };
  }
  if (payload.protocol !== PROTOCOL) {
    return {
      ok: false,
      reason: "MALFORMED",
      detail: `protocol must be ${JSON.stringify(PROTOCOL)}`,
    };
  }
  if (!SUPPORTED_VERSIONS.has(payload.version)) {
    return {
      ok: false,
      reason: "UNKNOWN_VERSION",
      detail: `version ${JSON.stringify(payload.version)} is not supported`,
    };
  }
  if (!KNOWN_TYPES.has(payload.type)) {
    // Fails closed. An admitted event reads as a counted one.
    return {
      ok: false,
      reason: "UNKNOWN_VERSION",
      detail: `unregistered event type ${JSON.stringify(payload.type)}`,
    };
  }
  if (!Array.isArray(proofs) || proofs.length === 0) {
    return {
      ok: false,
      reason: "MALFORMED",
      detail: "an envelope with no proof asserts nothing",
    };
  }

  const results = [];
  for (const proof of proofs) {
    results.push({ signer: proof && proof.signer, ...(await verifyProof(payload, proof)) });
  }
  // At least one proof must verify, and only the ones that do become signers.
  // A bad proof used to condemn the envelope, which made *appending* a way of
  // *deleting*: proofs sit outside the payload and do not change the event id,
  // so anyone holding no key can append nonsense to a copy and have that copy
  // thrown away whole. A mirror serving only the spoiled copy makes the event
  // vanish -- the omission attack the union merge exists to prevent, landed at
  // the door. Nothing is gained by appending: a forged proof names a signer who
  // is absent from `signers`, and that is the list every quorum count reads.
  // (D-087, revising D-027. The Python side does the same thing.)
  const failed = results.filter((r) => !r.ok);
  const verified = results.filter((r) => r.ok);
  if (verified.length === 0) {
    return {
      ok: false,
      reason: "INVALID_SIGNATURE",
      detail: failed.map((r) => `${r.signer}: ${r.reason}`).join("; "),
      proofs: results,
      signers: [],
      warnings,
    };
  }
  if (failed.length > 0) {
    warnings.push(
      `${failed.length} proof(s) did not verify and were discarded; they confer ` +
        "nothing. Anyone can append a proof without a key.",
    );
  }

  return {
    ok: true,
    reason: "SIGNATURE_VERIFIED",
    detail: `${verified.length} of ${results.length} proof(s) verified`,
    eventId: await eventId(payload),
    signers: [...new Set(verified.map((r) => r.signer))].sort(),
    proofs: results,
    warnings,
  };
}

export const IMPLEMENTATION = {
  name: "lineageauth-js",
  protocol: PROTOCOL,
  versions: [...SUPPORTED_VERSIONS],
  note:
    "A second implementation, written to disagree with the first. JCS, base58btc, " +
    "the multicodec check, the preimage and the event id are re-derived from the " +
    "specification rather than ported. SHA-256 and Ed25519 come from WebCrypto, " +
    "because a hand-rolled curve would add risk without adding evidence.",
};
