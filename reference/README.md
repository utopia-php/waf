# WAF Challenge — JS reference

Version-locked JavaScript companions to the PHP `Utopia\WAF\Challenge`
primitives. These are the **single source of truth** for the challenge
solver used by two consumers:

- the **edge browser interstitial** (`Utopia\WAF\Challenge\Interstitial` inlines
  this algorithm), and
- the **web + node SDK retry interceptors**.

Keeping them here, next to the primitives, means the solver and the
`DIFFICULTY_DEFAULT_*` constants change together.

## Files

| File | Purpose |
| --- | --- |
| `solver.js` | Dependency-free pure-JS SHA-256 + challenge solver. `solve()` (chunked/yielding, for browsers) and `solveSync()` (blocking, for node). Mirrors the PHP `Verifier` leading-zero-bit rule exactly. |
| `interceptor.js` | Reference SDK retry interceptor: single-flight solve, token caching with a skew-safe deadline, one re-solve on a stale-token 403, never loops. |

## Contract

A client finds the smallest non-negative integer `solution` such that

```
sha256(nonce + '.' + solution)   has >= difficulty leading zero bits
```

then `POST`s `{ nonce, solution }` to `/v1/waf/challenge` (API) or
`/__waf/challenge` (edge site) to obtain a clearance token/cookie.

## Why pure-JS (not `crypto.subtle`)

`crypto.subtle.digest` is async and its per-call overhead makes a
digest-in-a-loop 10–100× slower than a tight synchronous JS implementation for
this access pattern. The browser solver therefore uses the inline function and
yields between chunks (`requestAnimationFrame`) to keep the tab responsive.

## Verified interop

`solver.js` is checked against the SHA-256 known-answer vector for `"abc"` and,
end-to-end, a nonce minted by the PHP `Issuer` is solved here and accepted by the
PHP `Verifier` — so browser/SDK solutions are valid server-side.

## SDK integration (phase 3)

The generated `appwrite`/`node-appwrite` SDKs wrap their transport with
`createInterceptor({ endpoint, projectId, doFetch })` and route all requests
through `interceptor.request(url, init)`. `doFetch` performs one raw request and
returns `{ status, headers, json }`. Web solves via `solve()`; node via
`solveSync()`. Ship web first (it exercises both the browser solver and the CORS
header exposure), then node.

## Benchmark gate (phase 1)

Before tagging `0.1.0`, run `solver.js` on the reference devices (mid-range
Android, ~3-gen-old iPhone/Safari, low-end laptop). Acceptance: **p95 solve ≤ 4 s**
on the mid-range Android at `DIFFICULTY_DEFAULT_BROWSER`. Challenge solve time is
exponentially distributed (p95 ≈ 3× median), so target median ≤ ~1.3 s. Set the
final `DIFFICULTY_DEFAULT_BROWSER` to the largest value that passes.
