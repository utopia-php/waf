<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * v2 scoring engine: a learned logistic-regression model.
 *
 * This is the payoff of the {@see Engine} seam. It consumes the exact same
 * {@see Signals} bag as {@see HeuristicEngine} and returns the same {@see Score},
 * so swapping the brain touches neither the signal collection nor the enforcement
 * code. The difference is the core: instead of hand-tuned additive weights over a
 * fixed denominator, the bot risk is a calibrated probability
 *
 *   P(bot) = sigmoid(intercept + Σ coefᵢ · signalᵢ)
 *
 * over the numeric signal vector ({@see self::FEATURES}). The coefficients are
 * learned offline from labelled traffic and baked in as constants — inference is
 * a dot product and one exp(), no runtime ML dependency. Retraining is the whole
 * update: regenerate the model and replace {@see self::DEFAULT_COEFFICIENTS} /
 * {@see self::DEFAULT_INTERCEPT}; see `reference/train-ml-engine.js`.
 *
 * There is no production traffic yet, so the shipped coefficients are fit on
 * synthetic labelled traffic that encodes the same domain assumptions the
 * heuristic weights did (bot archetypes vs. real-browser humans). The value here
 * is the path, not the exact numbers: once real challenge outcomes accumulate,
 * the same class serves a model trained on them.
 *
 * The decisive, non-fuzzy policy stays deterministic and identical to the
 * heuristic engine: a passed interaction challenge hard-caps the score, and a
 * request-inspection {@see Signal::ATTACK_SCORE} floors the verdict. Those are
 * rules, not things to learn — the model only decides the behavioural middle.
 */
final class MlEngine implements Engine
{
    /**
     * The ordered numeric feature vector the model consumes. Must match the
     * `features` array the trainer emits (`reference/ml-engine-model.json`).
     *
     * @var list<string>
     */
    public const FEATURES = [
        Signal::IP_REPUTATION,
        Signal::ASN_REPUTATION,
        Signal::TLS_MISMATCH,
        Signal::MISSING_HEADERS,
        Signal::HEADLESS,
        Signal::AUTOMATION_FLAGS,
        Signal::BEHAVIORAL_RISK,
    ];

    /**
     * Learned logistic-regression coefficients (signal key => weight), fit offline
     * on synthetic labelled traffic. Regenerate with `reference/train-ml-engine.js`.
     *
     * @var array<string, float>
     */
    public const DEFAULT_COEFFICIENTS = [
        Signal::IP_REPUTATION => 3.562063,
        Signal::ASN_REPUTATION => 4.67617,
        Signal::TLS_MISMATCH => 1.375458,
        Signal::MISSING_HEADERS => 1.896716,
        Signal::HEADLESS => 4.576935,
        Signal::AUTOMATION_FLAGS => 2.71498,
        Signal::BEHAVIORAL_RISK => 4.826937,
    ];

    /** Learned intercept (bias) — the all-zero-signal baseline logit. */
    public const DEFAULT_INTERCEPT = -6.52634;

    /** Score ceiling applied when the client passed the interaction challenge. */
    public const INTERACTION_PASS_CEILING = 0.10;

    /** ATTACK_SCORE at/above this floors the verdict to deny (a certain attack). */
    public const ATTACK_DENY_FLOOR = 0.85;

    /** ATTACK_SCORE at/above this floors the verdict to at least challenge. */
    public const ATTACK_CHALLENGE_FLOOR = 0.40;

    /**
     * @var array<string, float>
     */
    private array $coefficients;

    /**
     * @var array<string, float>
     */
    private array $thresholds;

    /**
     * @param array<string, float> $coefficients signal key => learned weight
     * @param float                $intercept    learned bias term
     * @param array<string, float> $thresholds   tier boundaries (see RiskTier::DEFAULT_THRESHOLDS)
     */
    public function __construct(
        array $coefficients = self::DEFAULT_COEFFICIENTS,
        private float $intercept = self::DEFAULT_INTERCEPT,
        array $thresholds = RiskTier::DEFAULT_THRESHOLDS,
    ) {
        $this->coefficients = $coefficients;
        $this->thresholds = $thresholds;
    }

    public function score(Signals $signals): Score
    {
        $logit = $this->intercept;
        $contributions = [];

        foreach ($this->coefficients as $key => $coefficient) {
            $value = $signals->float($key);
            if ($value === 0.0) {
                continue;
            }

            // Logit-space contribution: how many log-odds this signal added. Kept
            // for the same explainability the heuristic engine offers (the sink
            // logs it), even though the final score is the squashed probability.
            $term = $coefficient * $value;
            $contributions[$key] = $term;
            $logit += $term;
        }

        // Squash to a calibrated P(bot) in (0,1).
        $value = 1.0 / (1.0 + \exp(-$logit));

        // --- deterministic policy overrides (identical to HeuristicEngine) ---
        if ($signals->bool(Signal::INTERACTION_PASSED)) {
            $value = \min($value, self::INTERACTION_PASS_CEILING);
        }

        $attack = $signals->float(Signal::ATTACK_SCORE);
        if ($attack >= self::ATTACK_DENY_FLOOR) {
            $value = \max($value, $this->threshold(RiskTier::DENY));
        } elseif ($attack >= self::ATTACK_CHALLENGE_FLOOR) {
            $value = \max($value, $this->threshold(RiskTier::CHALLENGE));
        }

        $value = \max(0.0, \min(1.0, $value));

        return new Score($value, RiskTier::fromScore($value, $this->thresholds), $contributions);
    }

    private function threshold(RiskTier $tier): float
    {
        return $this->thresholds[$tier->value] ?? RiskTier::DEFAULT_THRESHOLDS[$tier->value] ?? 0.0;
    }
}
