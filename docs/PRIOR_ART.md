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
| the whole shape — delegation, provenance and verification for MCP and A2A agents | [AIP](https://arxiv.org/abs/2603.24775) (*Agent Identity Protocol for Verifiable Delegation Across MCP and A2A*, 2026), and [ADTP](https://github.com/Zahanturel/adtp) — the same shape as a running Go daemon on UCAN chains |

The last row is the uncomfortable one, and it has two entries.

**AIP** addresses the same problem for the same two agent protocols, and does so
by building on Biscuit rather than defining its own token — the choice this
project did not make. UCAN, for its part, already has implementations in Rust,
Go and TypeScript.

**ADTP** is the closer of the two, because it is not a paper. It is a Go daemon
its author describes as 12.6k lines under Apache-2.0 with a 22-finding security
audit resolved, doing agent-to-agent delegation over UCAN chains across MCP and
A2A. Its README states its own prior art before its own contribution, and
corrects an overclaim an earlier version of that README made. Anyone assessing
this project should read that one.

Where ADTP is ahead: its constraint language (`action_restrict`,
`parameter_schema`, `time_window`, cumulative budget metering) is richer than the
namespace/resource/action scopes here, and its cascade revocation — revoking any
element of a chain denies that chain and everything descending from it, checked
during the root walk rather than by enumerating descendants — is a stronger
statement than this project makes about revocation.

## What has not been demonstrated elsewhere, in this combination

Two things, and both are narrower than they sound.

**Epoch-based root succession with a recovery quorum, and conflict handling that
fails closed** (D-007, D-008, D-088). `did:key` cannot rotate, and none of UCAN,
ZCAP-LD, Biscuit or AIP defines continuity above the key.

ADTP is the interesting comparison, because it considered the problem and chose
the opposite answer: **"Key rotation = new did:key identity. All delegations
invalidated (strict, by design)."** An m-of-n org root quorum with 2-of-3 offline
keys does appear in its specification — inside `Appendix A — Roadmap (not
implemented)`, a section that opens by saying so.

So the claim here is narrower than "nobody else thought of it", and that is the
version worth making: two projects in this space reached opposite conclusions
about whether authority should survive a root key, and this one has its answer
running while the other has stated its own as not built. Whether preserving
delegations across a succession is *right* is a design question neither of us has
settled. KERI solved an adjacent problem with pre-rotation and did so first;
there is no priority claim here.

**Human approval bound to one exact action, such that approval cannot create
authority it was not granted** (D-009, D-010). Other designs place this at a
central authorization server and give up offline verification. Doing it offline
is the part we have not found elsewhere: the word "approval" does not occur in
ADTP's 651-line protocol specification, and UCAN's Receipt is an executor's
attestation after the fact rather than a human's consent before it.

A caveat that applies to both residuals: **not finding something is a statement
about the search.** Both were checked against documents rather than against the
code behind them, and neither author has been asked. Until one of them says so,
"not found" is all this page is entitled to claim.

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
the title given, on 2026-08-28. The ADTP quotations were read from its README and
`docs/PROTOCOL.md` on the same day. Assessments of overlap are judgements and may be
wrong; the citations are facts and should not be.*
