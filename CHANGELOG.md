# Changelog

## 0.6.0 - 2026-10-09

### Added

- Added generate_workspace_secret() and next_workspace_secret(), and the records.secret and records.secret_provider options.
- With a workspace secret set, records.emit() encrypts new records and returns both the record id and the wire record id; records.wire_id() gives the wire id for a webhook handler.
- records.history(), records.receipt() and records.bundle() open encrypted records with the workspace secret, a holder wrap or a record key, and check each entry against its sealed record hash.
- Added records.keep_copy(), records.record_key() and records.open(link, access_code).
- Added records.identity, records.holders, records.holdings and records.grants, with a pin store: wraps go only to workspaces whose code you confirmed.
- Added records.rotate() and records.rekey().

## 0.5.0 - 2026-10-02

- **fingerprint() now blinds by default and returns a Fingerprint with .ref and .blinding. Pass .ref as the payload, and save .blinding with write_blinding_file beside the file: a blinded entry can be checked only with it.**
- fingerprint(source) mixes a random 32-byte value into the fingerprint (alg hmac-sha-256), so it cannot be matched to a guessed file without the blinding file. The file's size is stored as before.
- For today's plain sha-256 fingerprint, pass blind=False or fingerprint(source, "sha-256") and use .ref.
- To check a file later, pass it with its blinding file: records.check(history, expect=[{"entry": 1, "files": [{"source": f, "blinding": b}]}]), or fingerprint(f, blinding=b). Fingerprinting the file again without its blinding file gives a different fingerprint, which does not match.
- records.emit and records.check refuse a Blinding, a blinding file or a Fingerprint before sending anything (RECORD_BLINDING_INCLUDED).
- json.dumps refuses a Blinding; log the ref instead.
- records.check now refuses an expected row or item it cannot read, instead of skipping it.
- If a blinding file is lost, its entry can no longer be matched to the file. The entry's seal still verifies.
- Before: ref = fingerprint(f) ... payloads=[ref]
- After: fp = fingerprint(f); write_blinding_file(path, fp.blinding) ... payloads=[fp.ref]

### Added

- `records.check` gives each entry a `kind`: `attempt`, `failure` or `transition`.
- Verifies a record disclosure and a kept copy (record-disclosure/v1, record-link-copy/v1), including v2 records' fields, up to their record hash against the record's seal history.
- `records.check` reads v2 record histories (record-history-bundle/v2) as well as v1.

## 0.4.0 - 2026-09-22

### Changed

- **Entries count from 1**, as every PacSpace page does. Through 0.3.0 the SDK took the wire's `seq` (counted from 0) under the name `entry`, so `amends={"entry": 1}` named the second entry while the record page called that one "Entry 2". Now `entry` is the entry's number as the pages show it, and the SDK converts at its boundary (`seq = entry - 1`) in `records.emit` (`amends["entry"]`, `references[]["entry"]`), `records.receipt(record, entry)`, `records.history(record, from_entry=, to_entry=)`, and `records.check` (`expect[]["entry"]`; each result's `entry` is now `seq + 1`). An `entry` below 1 raises `ValidationError` with the sentence that teaches the rule before anything is sent. A `"seq"` given in place of `"entry"` in `amends` or `references[]` goes on the wire as it is, for a caller reading it straight off a history or a webhook. The history file keeps the wire's `seq`. **If your code passed 0-based numbers, add 1.**
- User-Agent header bumped to `pacspace-sdk-python/0.4.0`.

## 0.3.0 - 2026-09-21

### Changed

- The default sandbox URL is `https://app.pacspace.io`, the same host as production. The API routes each request by the environment of its key, so a `pk_test_` key on the default host reads and writes the sandbox data plane; a `pk_live_` key on a sandbox-only host is refused with `API_KEY_ENVIRONMENT_HOST_MISMATCH` (403). `sandbox_url` stays as a bring-your-own override for a private sandbox host. The `api-sandbox` host keeps serving; nothing that names it breaks. Sandbox traffic on the default host shares the production host's throttle tiers.
- User-Agent header bumped to `pacspace-sdk-python/0.3.0`.

### Added

- Records: `records.emit(record=..., title=..., occurred_at=..., actor_id=..., payloads=[...], kind=None, amends=None, references=None)` writes an entry to a record (`machine-action-record` by default), `records.receipt(record, entry)` reads one entry's receipt, `records.history(record, from_entry=None, to_entry=None)` reads the record's history file, and `records.check(history, expect=None)` runs the check in your process. `fingerprint(...)` computes the payload reference (`sha-256`, `digest`, `byteLength`) an entry carries for a file. Landed in the repository on 2026-09-16 (Slice C5) and first published here.

- `Webhooks.verify` accepts an `X-PacSpace-Signature` header that carries more than one `v1=<hex>` value, comma separated. For 24 hours after a signing-secret rotation with overlap, PacSpace signs each delivery with the current secret and the previous one; the event is genuine when any one value matches the secret you hold, and each comparison is constant time. A single-value header verifies exactly as before.
- `balance.emit(..., {"adjusts": ...})` sends `adjusts` (`referenceId` or `recordId`) on `POST /api/v1/balance/delta`. `records.emit(..., amends=...)` already maps `entry` to wire `seq`; the README now shows both.

## 0.2.0 - 2026-05-28

### Changed

- Default production base URL is now `https://app.pacspace.io`, the single consolidated app/API origin (see ADR 0004). The previous `https://api.pacspace.io` host is being retired and is not maintained as a long-term default; pass `production_url` to target a custom host.
- User-Agent header bumped to `pacspace-sdk-python/0.2.0`.

### Added

- Invoice-proof payload normalization now preserves `verificationApiUrl`, the machine verification endpoint for tools, agents, and auditors.

### Deprecated

- `verificationExplorerUrl` remains available for compatibility but is deprecated. Use `verificationApiUrl` for machine verification and `verifyUrl` for human invoice links.

## 0.1.2 - 2026-05-06

### Behavior changes

- When a tenant has Shared Record enabled and a customer handle exists, invoice bundle URL fields such as `verifyUrl` may resolve to the persistent customer permalink (`/c/{handle}`) instead of a period-specific receipt URL. Treat URL fields as opaque strings and use explicit receipt/checkpoint identifiers for period parsing.

### Added

- Shared Record invoice bundles may include additive fields such as `accessHint`, `customerLinkUrl`, and `customerLinkHost` when exposed by the API. Existing receipt URL fields remain strings.

Available in source only; PyPI publish is handled by a separate follow-up plan.

## 0.2.0 - 2026-04-16

### Breaking changes

- `derive()` and `compare()` now align to scoped behavior (current UTC month default on the API side).
- Requests that combine `startingCheckpoint` with `period` / `timePreset` / `startDate` / `endDate` are rejected by client-side runtime validation.

### Added

- Scope support for derive and compare options (`period`, `timePreset`, `startDate`, `endDate`).
- Runtime scope-mode validation guards for derive/compare option combinations.
- Convenience methods:
  - `derive_current_month(customer_id, options=None)`
  - `derive_for_period(customer_id, period, options=None)`
  - `derive_months_back(customer_id, months, options=None)`
- `customer(..., {"period": "YYYY-MM"})` support.
- Typed error classes:
  - `InvalidScopeCombinationError`
  - `ScopeTooWideError`

### Migration guide

1. Use explicit scope fields when deriving across multiple months.
2. Keep checkpoint-based replay requests checkpoint-only (no scope fields in the same request).
3. If you need month-pinned customer record views, include `period` in customer detail calls.
