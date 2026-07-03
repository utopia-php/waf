<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * Destination for {@see SignalRecord}s — the write side of the data pipeline.
 *
 * The library defines the contract; each surface supplies its own implementation
 * (cloud → its usage/event pipeline into ClickHouse; edge → its logs stream).
 * Recording MUST be best-effort and non-blocking: a sink failure can never affect
 * the request's WAF decision.
 */
interface Sink
{
    public function record(SignalRecord $record): void;
}
