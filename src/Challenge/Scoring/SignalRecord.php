<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * A decision-time snapshot for the data pipeline: the signals seen, the score
 * they produced, and the verdict — the raw material an ML model trains on later.
 *
 * Emitted on every scored request (see {@see Sink}). The `enforced` flag
 * separates shadow-mode observations (scored but not acted on) from live
 * decisions, so the measurement harness can compare the two without contaminating
 * the training set. Downstream outcomes (banned account, chargeback, honeypot
 * hit, conversion) are logged separately and joined to this record offline via
 * `requestId`.
 */
final readonly class SignalRecord
{
    public function __construct(
        public string $projectId,
        public string $audience,
        public string $ipPrefix,
        public Signals $signals,
        public Score $score,
        public RiskTier $decision,
        public bool $enforced,
        public int $issuedAt,
        public string $requestId = '',
    ) {
    }

    /**
     * Flatten to a log/analytics-friendly row.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'type' => 'waf.score',
            'projectId' => $this->projectId,
            'audience' => $this->audience,
            'ipPrefix' => $this->ipPrefix,
            'requestId' => $this->requestId,
            'issuedAt' => $this->issuedAt,
            'score' => $this->score->value,
            'tier' => $this->score->tier->value,
            'decision' => $this->decision->value,
            'enforced' => $this->enforced,
            'signals' => $this->signals->toArray(),
            'contributions' => $this->score->contributions,
        ];
    }
}
