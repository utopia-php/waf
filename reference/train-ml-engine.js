#!/usr/bin/env node
/**
 * Trainer for the WAF bot-detection MlEngine (logistic regression).
 *
 * The MlEngine is the v2 scoring brain: it implements the same
 * `Utopia\WAF\Challenge\Scoring\Engine` interface as the v1 HeuristicEngine, but
 * replaces the hand-tuned weighted-additive core with a *learned* logistic model
 *   P(bot) = sigmoid(intercept + Σ coefᵢ · featureᵢ)
 * over the numeric signal vector. The deterministic policy overrides
 * (interaction ceiling, attack-score deny/challenge floors) stay in the engine —
 * only the fuzzy behavioural middle is learned.
 *
 * There is no production traffic to train on, so this fits the model on
 * *synthetic* labelled traffic that encodes the same domain assumptions the
 * heuristic weights encoded — several bot archetypes vs. real-browser humans.
 * The point is not the exact numbers; it is the swap path: retrain → paste the
 * emitted coefficients into MlEngine::DEFAULT_COEFFICIENTS, nothing else changes.
 *
 * Deterministic: seeded PRNG, so the baked constants are reproducible.
 *
 *   node reference/train-ml-engine.js            # prints report + JSON model
 *   node reference/train-ml-engine.js > reference/ml-engine-model.json
 */
'use strict';

// Feature order — MUST match MlEngine::FEATURES.
const FEATURES = [
  'ipReputation',
  'asnReputation',
  'tlsMismatch',
  'missingHeaders',
  'headless',
  'automationFlags',
  'behavioralRisk',
];

// ---- seeded PRNG (mulberry32) so training is reproducible ----------------
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(0x5eed1234);
const clamp01 = (x) => Math.max(0, Math.min(1, x));
// non-negative gaussian-ish noise in [0,1]
const near = (mu, spread) => clamp01(mu + (rnd() - 0.5) * 2 * spread);
const pick = (arr) => arr[Math.floor(rnd() * arr.length)];

// ---- synthetic sample generators -----------------------------------------
function humanSample() {
  // Real browser, a person driving it. Occasional benign noise (a VPN, a proxy
  // that strips one header) but never automation/headless artefacts.
  return {
    ipReputation: rnd() < 0.08 ? near(0.15, 0.15) : 0,
    asnReputation: rnd() < 0.15 ? near(0.2, 0.2) : 0, // some legit users on VPN/hosting ASNs
    tlsMismatch: rnd() < 0.02 ? 1 : 0, // a real browser's JA4 matches its UA
    missingHeaders: rnd() < 0.2 ? near(0.15, 0.15) : 0,
    headless: 0,
    automationFlags: 0,
    behavioralRisk: near(0.12, 0.12), // humans move the mouse / type
    label: 0,
  };
}

function botSample() {
  // Three archetypes, sampled uniformly.
  const kind = pick(['headless', 'scripted', 'datacenter']);
  if (kind === 'headless') {
    // Puppeteer/Selenium: real Chrome TLS, but webdriver + no human input.
    return {
      ipReputation: rnd() < 0.3 ? near(0.4, 0.3) : 0,
      asnReputation: near(0.5, 0.4),
      tlsMismatch: rnd() < 0.2 ? 1 : 0,
      missingHeaders: near(0.15, 0.15),
      headless: near(0.9, 0.1),
      automationFlags: near(0.6, 0.4),
      behavioralRisk: near(0.85, 0.15), // no organic interaction
      label: 1,
    };
  }
  if (kind === 'scripted') {
    // curl / python-requests hitting the interstitial: no JS engine at all, so
    // the client probe reports fully headless; TLS fingerprint gives it away.
    return {
      ipReputation: rnd() < 0.4 ? near(0.5, 0.4) : 0,
      asnReputation: near(0.6, 0.35),
      tlsMismatch: rnd() < 0.9 ? 1 : 0,
      missingHeaders: near(0.5, 0.3),
      headless: 1,
      automationFlags: near(0.3, 0.3),
      behavioralRisk: 1,
      label: 1,
    };
  }
  // datacenter: abusive IP/ASN reputation dominant, mixed client artefacts.
  return {
    ipReputation: near(0.75, 0.25),
    asnReputation: near(0.8, 0.2),
    tlsMismatch: rnd() < 0.5 ? 1 : 0,
    missingHeaders: near(0.35, 0.3),
    headless: rnd() < 0.6 ? near(0.8, 0.2) : 0,
    automationFlags: rnd() < 0.5 ? near(0.5, 0.4) : 0,
    behavioralRisk: near(0.7, 0.3),
    label: 1,
  };
}

// balanced dataset
const N = 20000;
const data = [];
for (let i = 0; i < N; i++) data.push(i % 2 === 0 ? humanSample() : botSample());

// ---- logistic regression (full-batch gradient descent, L2) ---------------
const D = FEATURES.length;
let w = new Array(D).fill(0);
let b = 0;
const lr = 0.5;
const l2 = 1e-4;
const epochs = 4000;
const sigmoid = (z) => 1 / (1 + Math.exp(-z));

for (let e = 0; e < epochs; e++) {
  const gw = new Array(D).fill(0);
  let gb = 0;
  for (const s of data) {
    let z = b;
    for (let j = 0; j < D; j++) z += w[j] * s[FEATURES[j]];
    const err = sigmoid(z) - s.label;
    for (let j = 0; j < D; j++) gw[j] += err * s[FEATURES[j]];
    gb += err;
  }
  for (let j = 0; j < D; j++) w[j] -= lr * (gw[j] / N + l2 * w[j]);
  b -= lr * (gb / N);
}

// ---- evaluate -------------------------------------------------------------
let tp = 0, tn = 0, fp = 0, fn = 0;
const predict = (s) => {
  let z = b;
  for (let j = 0; j < D; j++) z += w[j] * s[FEATURES[j]];
  return sigmoid(z);
};
for (const s of data) {
  const p = predict(s) >= 0.5 ? 1 : 0;
  if (s.label === 1 && p === 1) tp++;
  else if (s.label === 0 && p === 0) tn++;
  else if (s.label === 0 && p === 1) fp++;
  else fn++;
}

const coefficients = {};
FEATURES.forEach((f, j) => (coefficients[f] = Number(w[j].toFixed(6))));
const model = {
  _comment: 'Generated by reference/train-ml-engine.js — logistic regression over the bot-detection signal vector. Paste into MlEngine::DEFAULT_COEFFICIENTS / DEFAULT_INTERCEPT.',
  features: FEATURES,
  intercept: Number(b.toFixed(6)),
  coefficients,
  metrics: {
    samples: N,
    accuracy: Number(((tp + tn) / N).toFixed(4)),
    precision: Number((tp / (tp + fp)).toFixed(4)),
    recall: Number((tp / (tp + fn)).toFixed(4)),
    falsePositiveRate: Number((fp / (fp + tn)).toFixed(4)),
  },
};

// canonical decision vectors — a sanity check on tier alignment
const THRESH = { challenge: 0.25, interactive: 0.55, deny: 0.8 };
const tier = (p) => (p >= THRESH.deny ? 'deny' : p >= THRESH.interactive ? 'interactive' : p >= THRESH.challenge ? 'challenge' : 'allow');
const vec = (o) => { const s = {}; FEATURES.forEach((f) => (s[f] = o[f] || 0)); return predict(s); };
const cases = {
  'clean human': vec({}),
  'one missing header': vec({ missingHeaders: 0.33 }),
  'legit VPN user': vec({ asnReputation: 0.3, missingHeaders: 0.33 }),
  'headless bot (no interaction)': vec({ headless: 1, automationFlags: 0.66, behavioralRisk: 1 }),
  'curl/python (tls mismatch)': vec({ tlsMismatch: 1, missingHeaders: 0.5, headless: 1, behavioralRisk: 1 }),
  'datacenter abuser': vec({ ipReputation: 0.8, asnReputation: 0.9 }),
};
const report = {};
for (const [k, p] of Object.entries(cases)) report[k] = { p: Number(p.toFixed(4)), tier: tier(p) };
model.canonicalCases = report;

process.stdout.write(JSON.stringify(model, null, 2) + '\n');
process.stderr.write(
  `trained on ${N} samples — acc=${model.metrics.accuracy} prec=${model.metrics.precision} recall=${model.metrics.recall} fpr=${model.metrics.falsePositiveRate}\n`
);
for (const [k, r] of Object.entries(report)) process.stderr.write(`  ${k.padEnd(32)} p=${r.p.toFixed(4)} → ${r.tier}\n`);
