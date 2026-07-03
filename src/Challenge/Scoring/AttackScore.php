<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * Normalizes a request-inspection anomaly score (Coraza / OWASP CRS points) into
 * the [0,1] {@see Signal::ATTACK_SCORE} value the scoring engine consumes.
 *
 * CRS assigns points per matched rule (critical=5, error=4, warning=3, notice=2)
 * and blocks when the inbound total crosses a threshold (5 at paranoia level 1).
 * We map points so that one critical hit reads as "half-confident" and roughly
 * two thresholds' worth reads as certain — the engine's deny-floor then makes a
 * certain attack decisive.
 */
final class AttackScore
{
    /** Anomaly points treated as a certain attack (≈ 2× the CRS inbound threshold). */
    public const POINTS_FOR_CERTAIN = 10;

    public static function normalize(int $points): float
    {
        if ($points <= 0) {
            return 0.0;
        }

        return \min(1.0, $points / self::POINTS_FOR_CERTAIN);
    }
}
