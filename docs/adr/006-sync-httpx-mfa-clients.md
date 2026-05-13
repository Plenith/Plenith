# ADR 006: Synchronous httpx in Duo/Okta/Twilio clients

**Status:** Accepted
**Date:** 2026-05

## Context

The MFA gateway runs asyncio. The Duo / Okta / Twilio providers each
have their own SDK style: Duo offers a sync requests-style client,
Okta has both a sync REST client and an async one, Twilio's official
SDK is sync only.

## Decision

**Plenith implements its own thin httpx-based clients for all
three.** We do NOT use the vendor SDKs.

## Why

1. **One dep, three providers.** httpx is already in `requirements.txt`
   for our outbound SIEM/SOAR clients. Pulling in Duo's SDK adds 2
   transitive deps, Okta's adds 5, Twilio's adds 11.
2. **Async-native everywhere.** Our async httpx client integrates
   directly with the MFA gateway's event loop. The vendor SDKs would
   require `asyncio.to_thread` wrapping or maintaining their own
   eventloop bridges.
3. **The API surfaces are TINY.** Duo's flow is request_push → poll.
   Okta's is resolve_user → list_factors → verify → poll. Twilio's is
   POST Verification → GET Verification. All three are 50-100 lines.
4. **Vendor-SDK churn is real.** Duo deprecated their v1 SDK in 2024;
   Okta's Python SDK had three rewrites between 2021-2025. Owning the
   wire protocol means our code keeps working as long as their REST
   contract does (much more stable than the SDK).

## Considered alternatives

- **Each vendor's official SDK.** Heavier deps, sync/async impedance.
- **`httpx.AsyncClient` + per-provider modules** (current choice).
- **A meta-MFA library** (mfaverify, py-mfa-providers, etc.) — none
  with v2-quality maintenance.

## Consequences

- **We track each provider's API spec ourselves.** Duo's HMAC signature
  rules, Okta's Factors API quirks, Twilio's Verification status enum.
- **No vendor-side SDK bug-fix freebies.** When Duo fixes a bug in
  their SDK, we don't get it automatically.
- **Future-proofing:** the contract surface in `mfa_providers.py` is
  small enough (each provider class is ~70 lines) that swapping for
  vendor SDKs later is trivial if the calculus changes.

## File pointers

- `plenith/connectors/mfa_providers.py`
- `linux-fork/mfa/mfa_gateway.py::_maybe_run_push`
