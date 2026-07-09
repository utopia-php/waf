<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * The enforcement tier a risk score maps to — the escalation ladder.
 *
 *   allow        → let the request through untouched
 *   challenge    → impose the silent (invisible) attestation check
 *   interactive  → impose the interaction / first-party captcha (humanity gate)
 *   deny         → block outright
 *
 * The interactive tier needs a browser page, so it only applies at the edge;
 * the cloud API surface clamps it down (see {@see self::clampTo()}).
 */
enum RiskTier: string
{
    case ALLOW = 'allow';
    case CHALLENGE = 'challenge';
    case INTERACTIVE = 'interactive';
    case DENY = 'deny';

    /**
     * Default score→tier boundaries. A score at or above a boundary escalates to
     * that tier. Deliberately conservative: a request only reaches a gate when a
     * meaningful share of signal weight points at it, keeping false positives low.
     *
     * @var array<string, float>
     */
    public const DEFAULT_THRESHOLDS = [
        self::CHALLENGE->value => 0.25,
        self::INTERACTIVE->value => 0.55,
        self::DENY->value => 0.80,
    ];

    /**
     * Map a [0,1] risk score to a tier using the given (or default) boundaries.
     *
     * @param array<string, float> $thresholds
     */
    public static function fromScore(float $score, array $thresholds = self::DEFAULT_THRESHOLDS): self
    {
        $score = \max(0.0, \min(1.0, $score));

        if ($score >= ($thresholds[self::DENY->value] ?? self::DEFAULT_THRESHOLDS[self::DENY->value])) {
            return self::DENY;
        }
        if ($score >= ($thresholds[self::INTERACTIVE->value] ?? self::DEFAULT_THRESHOLDS[self::INTERACTIVE->value])) {
            return self::INTERACTIVE;
        }
        if ($score >= ($thresholds[self::CHALLENGE->value] ?? self::DEFAULT_THRESHOLDS[self::CHALLENGE->value])) {
            return self::CHALLENGE;
        }

        return self::ALLOW;
    }

    /**
     * Clamp a tier to what a surface can actually enforce. The cloud API has no
     * browser page, so it cannot render the interactive slider — an interactive
     * verdict falls back to the silent (invisible) attestation check. Every other
     * tier (including deny) is surface-agnostic.
     *
     * Note: the silent attestation itself is browser-collected, so a non-browser
     * API client cannot satisfy it either; on that surface the challenge tier is
     * effectively "score on server signals alone" (see the cloud integration).
     */
    public function clampTo(bool $interactiveCapable): self
    {
        if ($this === self::INTERACTIVE && !$interactiveCapable) {
            return self::CHALLENGE;
        }

        return $this;
    }
}
