<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * Immutable, normalized bag of bot-detection signals for a single request.
 *
 * A raw feature container keyed by {@see Signal} constants. It carries no
 * scoring logic — an {@see Engine} interprets it — so the same bag serves the
 * heuristic engine today and an ML engine later without a schema change.
 */
final class Signals
{
    /**
     * @param array<string, mixed> $values signal key => value
     */
    public function __construct(
        private readonly array $values = [],
    ) {
    }

    /**
     * Return a copy with one signal set (or replaced). Immutable.
     */
    public function with(string $key, mixed $value): self
    {
        return new self([...$this->values, $key => $value]);
    }

    public function has(string $key): bool
    {
        return \array_key_exists($key, $this->values);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    /**
     * Read a signal as a bot-risk float clamped to [0,1]. Booleans map to
     * 1.0/0.0; anything unset or non-numeric returns the default.
     */
    public function float(string $key, float $default = 0.0): float
    {
        if (!$this->has($key)) {
            return $default;
        }

        $value = $this->values[$key];
        if (\is_bool($value)) {
            return $value ? 1.0 : 0.0;
        }
        if (!\is_numeric($value)) {
            return $default;
        }

        return \max(0.0, \min(1.0, (float) $value));
    }

    public function bool(string $key, bool $default = false): bool
    {
        return $this->has($key) ? (bool) $this->values[$key] : $default;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->values;
    }
}
