<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * A {@see Sink} that discards records. The safe default when no data pipeline is
 * wired, so scoring can run without a sink present.
 */
final class NullSink implements Sink
{
    public function record(SignalRecord $record): void
    {
        // intentionally does nothing
    }
}
