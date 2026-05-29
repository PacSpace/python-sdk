# Changelog

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
