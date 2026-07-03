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
        }

        $value = \max(0.0, \min(1.0, $risk));

        if ($signals->bool(Signal::INTERACTION_PASSED)) {
            $value = \min($value, self::INTERACTION_PASS_CEILING);
        }

        return new Score($value, RiskTier::fromScore($value, $this->thresholds), $contributions);
    }
}
