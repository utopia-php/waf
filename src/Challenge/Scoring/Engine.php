<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * A bot-detection scoring engine: turns a normalized signal bag into a risk score.
 *
 * This is the swap point the whole design hinges on. v1 is {@see HeuristicEngine}
 * (weighted thresholds); a future v2 ML model implements the same interface, so
 * upgrading the brain never touches the collection or enforcement code.
 */
interface Engine
{
    public function score(Signals $signals): Score;
}
