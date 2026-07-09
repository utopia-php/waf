<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * v1 scoring engine: a weighted additive heuristic.
 *
 * Each known signal contributes `value * weight` to a running total, divided by
 * the *fixed* sum of all weights (not just the present ones). The fixed
 * denominator is the conservative choice — a request with only one or two
 * signals present scores low, so missing telemetry never manufactures a high
 * risk. This keeps the false-positive rate down, which the plan calls the metric
 * that hurts most.
 *
 * A passed interaction challenge ({@see Signal::INTERACTION_PASSED}) is a strong
 * humanity assertion, so it hard-caps the score below the first gate regardless
 * of the other signals.
 *
 * Weights and thresholds are injectable so the measurement harness can tune them
 * (and, eventually, so an ML engine can replace this class wholesale).
 */
final class HeuristicEngine implements Engine
{
    /**
     * @var array<string, float>
     */
    public const DEFAULT_WEIGHTS = [
        Signal::IP_REPUTATION => 3.0,
        Signal::ASN_REPUTATION => 2.0,
        Signal::TLS_MISMATCH => 4.0,
        Signal::MISSING_HEADERS => 1.0,
        Signal::HEADLESS => 3.0,
        Signal::AUTOMATION_FLAGS => 3.0,
        Signal::BEHAVIORAL_RISK => 2.0,
    ];

    /** Score ceiling applied when the client passed the interaction challenge. */
    public const INTERACTION_PASS_CEILING = 0.10;

    /** ATTACK_SCORE at/above this floors the verdict to deny (a certain attack). */
    public const ATTACK_DENY_FLOOR = 0.85;

    /** ATTACK_SCORE at/above this floors the verdict to at least challenge. */
    public const ATTACK_CHALLENGE_FLOOR = 0.40;

    /**
     * @var array<string, float>
     */
    private array $weights;

    /**
     * @var array<string, float>
     */
    private array $thresholds;

    private float $totalWeight;

    /**
     * @param array<string, float> $weights    signal key => weight
     * @param array<string, float> $thresholds tier boundaries (see RiskTier::DEFAULT_THRESHOLDS)
     */
    public function __construct(
        array $weights = self::DEFAULT_WEIGHTS,
        array $thresholds = RiskTier::DEFAULT_THRESHOLDS,
    ) {
        $this->weights = $weights;
        $this->thresholds = $thresholds;
        $this->totalWeight = \array_sum($weights);
    }

    public function score(Signals $signals): Score
    {
        $contributions = [];
        $risk = 0.0;
        $serverRisk = 0.0;

        foreach ($this->weights as $key => $weight) {
            if (!$signals->has($key) || $this->totalWeight <= 0.0) {
                continue;
            }

            $contribution = $signals->float($key) * $weight / $this->totalWeight;
            if ($contribution === 0.0) {
                continue;
            }

            $contributions[$key] = $contribution;
            $risk += $contribution;

            // Track the server-observed portion separately (see the interaction
            // cap below).
            if (\in_array($key, Signal::SERVER, true)) {
                $serverRisk += $contribution;
            }
        }

        $value = \max(0.0, \min(1.0, $risk));
        $serverValue = \max(0.0, \min(1.0, $serverRisk));

        if ($signals->bool(Signal::INTERACTION_PASSED)) {
            // A passed interaction is a humanity assertion about *behaviour*, so it
            // caps the client-behavioral noise (headless/automation/biometrics)
            // below the first gate — but it must not floor the score under the
            // server-observed evidence (IP/ASN reputation, TLS mismatch, missing
            // headers), which the client cannot legitimately assert away. Without
            // this floor a forged `interacted:true` would erase a blocklisted IP.
            $value = \max($serverValue, \min($value, self::INTERACTION_PASS_CEILING));
        }

        // Attacks are decisive, not fuzzy. A request-inspection verdict floors the
        // score to the matching gate — kept OUT of the weighted sum so it can't be
        // diluted, and applied AFTER the interaction cap so a solved challenge
        // never excuses an injection. High confidence ⇒ deny (you block an attack,
        // you don't challenge it); moderate ⇒ at least challenge.
        $attack = $signals->float(Signal::ATTACK_SCORE);
        if ($attack >= self::ATTACK_DENY_FLOOR) {
            $value = \max($value, $this->threshold(RiskTier::DENY));
        } elseif ($attack >= self::ATTACK_CHALLENGE_FLOOR) {
            $value = \max($value, $this->threshold(RiskTier::CHALLENGE));
        }

        return new Score($value, RiskTier::fromScore($value, $this->thresholds), $contributions);
    }

    private function threshold(RiskTier $tier): float
    {
        return $this->thresholds[$tier->value] ?? RiskTier::DEFAULT_THRESHOLDS[$tier->value] ?? 0.0;
    }
}
