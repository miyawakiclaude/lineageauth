# 22 — Final Security Threat Model

## Threats

- operational key theft
- root key theft/loss
- recovery key theft
- resolver omission
- stale status
- malicious indexer
- replay
- TOCTOU
- prompt injection
- confused deputy
- semantic GET write
- XSS
- SSRF
- URL auto-fetch
- scope escalation
- forged attestations
- fake adoption/Sybil
- jury collusion
- task spam
- dependency compromise
- log leakage
- secret leakage

## Required controls

### Keys
- local signer
- offline root/recovery recommendation
- wallet isolation
- no private keys in browser
- no private seeds as CLI args

### Authority
- deny-by-default
- attenuation
- revocation
- epoch
- conflict fail-closed

### Approval
- exact action
- short expiry
- random nonce
- replay store
- final re-check

### Network
- allowlist semantic endpoint classes
- SSRF prevention
- no untrusted URL auto-fetch
- TLS in production

### UI
- CSP
- escaping
- no raw HTML
- link safety

### Evidence
- distinguish self-claim / signed claim / independent attestation
- do not promote repeated collusive attestations invisibly

### Jury
- disclose conflicts
- quorum
- signed votes
- no legal claims

### Availability
- short TTL
- stale label

## Production security gates

- dependency scan
- SAST
- fuzz parsers
- property tests authorization
- secrets scan
- threat review before enabling any external write automation
