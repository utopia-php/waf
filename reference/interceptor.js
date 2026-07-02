// Reference WAF-challenge retry interceptor for the Appwrite SDKs (web + node).
//
// This is the canonical behaviour the generated SDKs wrap around their transport
// (fetch on web, https/undici on node). It is intentionally transport-agnostic:
// pass a `doFetch` that performs one request and returns { status, headers, json }.
//
// Behaviour (HLD §2.4):
//   1. Trigger only on a response whose error type is 'waf_challenge_required'.
//   2. Read the challenge parameters from the CORS-exposed X-Appwrite-WAF-* headers.
//   3. SINGLE-FLIGHT: N concurrent requests that all 403 share ONE solve, keyed by
//      (endpoint, projectId, nonce-audience); all retry with the minted token.
//   4. Solve with solver.js, POST /v1/waf/challenge, cache { token, deadline }.
//      deadline = now + expiresIn - 30s (skew margin; prefer expiresIn over the
//      absolute Expires so a wrong local clock cannot shorten/extend the window).
//   5. Attach X-Appwrite-WAF-Token on subsequent requests while now < deadline.
//   6. On a challenge 403 DESPITE a cached token (expiry race / IP change): drop
//      the cache, re-solve ONCE, then surface the error. Never loop.

'use strict';

const { solve, solveSync } = require('./solver.js');

const CHALLENGE_ERROR = 'waf_challenge_required';
const DEADLINE_SKEW_SECONDS = 30;

// Solve in a browser (yielding) when available, else synchronously (node).
function solveChallenge(nonce, difficulty) {
  return (typeof window !== 'undefined')
    ? solve(nonce, difficulty)
    : Promise.resolve(solveSync(nonce, difficulty));
}

function isChallenge(res) {
  if (!res || res.status !== 403) return false;
  const body = res.json || {};
  return body.type === CHALLENGE_ERROR;
}

function readChallenge(res) {
  const h = res.headers || {};
  const get = (k) => h[k] || h[k.toLowerCase()] || '';
  return {
    nonce: get('X-Appwrite-WAF-Nonce'),
    difficulty: parseInt(get('X-Appwrite-WAF-Difficulty') || '0', 10) || 0,
    expiresIn: parseInt(get('X-Appwrite-WAF-Expires-In') || '0', 10) || 0,
  };
}

/**
 * Create an interceptor bound to one project/endpoint.
 *
 * @param {object}   opts
 * @param {string}   opts.endpoint  e.g. https://cloud.appwrite.io/v1
 * @param {string}   opts.projectId
 * @param {(url:string, init:object)=>Promise<{status:number,headers:object,json:any}>} opts.doFetch
 * @param {()=>number} [opts.now]   injectable clock (seconds), for tests
 */
function createInterceptor(opts) {
  const now = opts.now || (() => Math.floor(Date.now() / 1000));
  const key = opts.endpoint + '|' + opts.projectId; // single-flight + cache key
  const cache = new Map();      // key -> { token, deadline }
  const inflight = new Map();   // key -> Promise<token>  (single-flight)

  async function mintToken(res) {
    // Coalesce concurrent solves for the same audience.
    if (inflight.has(key)) return inflight.get(key);

    const p = (async () => {
      const { nonce, difficulty, expiresIn } = readChallenge(res);
      const solution = await solveChallenge(nonce, difficulty);
      const solveRes = await opts.doFetch(opts.endpoint + '/waf/challenge', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-appwrite-project': opts.projectId },
        body: JSON.stringify({ nonce, solution }),
      });
      if (solveRes.status < 200 || solveRes.status >= 300) {
        throw new Error('waf challenge solve failed: ' + solveRes.status);
      }
      const token = (solveRes.json || {}).token;
      const ttl = (solveRes.json || {}).expiresIn || expiresIn;
      cache.set(key, { token, deadline: now() + ttl - DEADLINE_SKEW_SECONDS });
      return token;
    })().finally(() => inflight.delete(key));

    inflight.set(key, p);
    return p;
  }

  function attachToken(init) {
    const cached = cache.get(key);
    if (cached && now() < cached.deadline) {
      init = init || {};
      init.headers = Object.assign({}, init.headers, { 'X-Appwrite-WAF-Token': cached.token });
    }
    return init;
  }

  // Wrap a single request with challenge handling. `alreadyRetried` guards the
  // "re-solve once on a stale-token 403" path so we can never loop.
  async function request(url, init, alreadyRetried) {
    const res = await opts.doFetch(url, attachToken(init));
    if (!isChallenge(res)) return res;

    if (alreadyRetried) return res; // solved-and-still-challenged: surface it
    if (cache.has(key)) cache.delete(key); // stale token — drop and re-solve once

    await mintToken(res);
    return request(url, init, true);
  }

  return { request, _cache: cache };
}

module.exports = { createInterceptor, isChallenge, readChallenge, solveChallenge };
