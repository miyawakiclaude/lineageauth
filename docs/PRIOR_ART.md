# Relationship to prior art

The first question a knowledgeable reader asks is "how is this different from
UCAN?", and until 2026-08-28 this repository had no answer anywhere in it. A
search of every document for `UCAN`, `ZCAP`, `Biscuit`, `macaroon`, `KERI`,
`in-toto`, `SLSA`, `Sigstore`, `SPIFFE` and `DSSE` returned nothing. That was
not a considered position; it was an omission, and a fair reader would take it
for a claim of novelty that had never been checked.

**LineageAuth claims no novelty in any single primitive.** Every layer below has
prior art, most of it more mature than this and some of it with several
independent implementations already — which is the thing `RELEASE.md` still
lists as the first requirement for v1 here.

## What is not new

| Layer here | Prior art |
|---|---|
| JCS canonicalization + SHA-256 + Ed25519 over `did:key` | the W3C [`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/) cryptosuite. Re-derived, not adopted. |
| delegation with monotonic attenuation, deny by default, offline verification | [UCAN 1.0](https://github.com/ucan-wg/spec), [ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/), [Biscuit](https://github.com/eclipse-biscuit/biscuit), macaroons |
| content-addressed subjects, predicate-typed statements, signatures held outside the payload | the [in-toto Attestation Framework](https://github.com/in-toto/attestation) and DSSE |
| the whole shape — delegation, provenance and verification for MCP and A2A agents | [AIP](https://arxiv.org/abs/2603.24775) (*Agent Identity Protocol for Verifiable Delegation Across MCP and A2A*, 2026) |

The last row is the uncomfortable one. AIP is not merely adjacent: it addresses
the same problem for the same two agent protocols, and it does so by building on
Biscuit rather than defining its own token — the choice this project did not
make. UCAN, for its part, already has implementations in Rust, Go and
TypeScript.

## What has not been demonstrated elsewhere, in this combination

Two things, and both are narrower than they sound.

**Epoch-based root succession with a recovery quorum, and conflict handling that
fails closed** (D-007, D-008, D-088). `did:key` cannot rotate, and none of UCAN,
ZCAP-LD, Biscuit or AIP defines continuity above the key. But KERI solves an
adjacent problem with pre-rotation and did so first; there is no priority claim
here.

**Human approval bound to one exact action, such that approval cannot create
authority it was not granted** (D-009, D-010). Other designs place this at a
central authorization server and give up offline verification. Doing it offline
is the part we have not found elsewhere.

Everything else — the impact graph, disputes, fleet transparency, the passport,
the router — is outside those standards' scope rather than better than them.
Being unclaimed is not the same as being demonstrated, and none of it is.

## The honest summary

The only claim available is the specific combination, under an
offline-verification constraint, and **that claim is unverified**. If you are
choosing a technology to depend on today, UCAN or Biscuit are more mature, have
been implemented by more people, and are the safer choice. This is pre-1.0 and
says so.

If you think a row above is wrong — that something here is already solved by a
standard, or that something dismissed is genuinely distinct — that is a useful
thing to say, and
[an issue](https://github.com/miyawakiclaude/lineageauth/issues) is the place.
Being told this is a reinvention is a better outcome than not being told.

---

*Every link above was checked to resolve, and the arXiv entry checked to carry
the title given, on 2026-08-28. Assessments of overlap are judgements and may be
wrong; the citations are facts and should not be.*
