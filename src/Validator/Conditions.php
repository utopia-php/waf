<?php

namespace Utopia\WAF\Validator;

use Utopia\Validator;
use Utopia\WAF\Condition;

class Conditions extends Validator
{
    public function __construct(
        private int $maxConditions = 100,
        private int $maxPayloadLength = 4096
    ) {
    }

    public function getDescription(): string
    {
        return 'Array of at least one WAF condition definition.';
    }

    public function isArray(): bool
    {
        return true;
    }

    public function isValid($value): bool
    {
        if (!\is_array($value)) {
            return false;
        }

        if (\count($value) === 0) {
            return false;
        }

        $count = 0;

        foreach ($value as $condition) {
            if (!\is_array($condition) || !$this->isValidCondition($condition, $count)) {
                return false;
            }
        }

        return true;
    }

    public function getType(): string
    {
        return self::TYPE_ARRAY;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function isValidCondition(array $payload, int &$count): bool
    {
        $count++;

        if ($this->maxConditions > 0 && $count > $this->maxConditions) {
            return false;
        }

        if ($this->maxPayloadLength > 0 && !$this->isWithinPayloadLimit($payload)) {
            return false;
        }

        $method = $payload['method'] ?? '';
        $values = $payload['values'] ?? [];

        if (\in_array($method, [Condition::TYPE_AND, Condition::TYPE_OR], true)) {
            if (!\is_array($values) || \count($values) === 0) {
                return false;
            }

            foreach ($values as $value) {
                if (!\is_array($value) || !$this->isValidCondition($value, $count)) {
                    return false;
                }
            }
        }

        try {
            Condition::fromArray($payload);
        } catch (\Throwable) {
            return false;
        }

        return true;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function isWithinPayloadLimit(array $payload): bool
    {
        try {
            $encoded = \json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return false;
        }

        return \strlen($encoded) <= $this->maxPayloadLength;
    }
}
