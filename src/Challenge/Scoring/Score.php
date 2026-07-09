<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * The result of scoring a {@see Signals} bag: a risk value, the tier it maps to,
 * and the per-signal contributions that produced it.
 *
 * `contributions` is what makes the score explainable (and tunable) — it records
 * how much each signal added to the total, which the measurement harness uses to
 * decide whether a signal earns its weight.
 */
final readonly class Score
{
    /**
     * @param float                $value         overall bot-risk in [0,1]
     * @param RiskTier             $tier          escalation tier for `value`
     * @param array<string, float> $contributions signal key => weighted contribution
     */
    public function __construct(
        public float $value,
        public RiskTier $tier,
        public array $contributions = [],
    ) {
    }
}
