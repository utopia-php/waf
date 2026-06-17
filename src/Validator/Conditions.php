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
        return 'Array of at least one WAF condition encoded as JSON strings.';
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

        $count = \count($value);

        if ($count === 0) {
            return false;
        }

        if ($this->maxConditions > 0 && $count > $this->maxConditions) {
            return false;
        }

        foreach ($value as $condition) {
            if (\is_string($condition)) {
                if ($this->maxPayloadLength > 0 && \strlen($condition) > $this->maxPayloadLength) {
                    return false;
                }

                try {
                    Condition::decode($condition);
                } catch (\Throwable) {
                    return false;
                }

                continue;
            }

            if (\is_array($condition)) {
                try {
                    Condition::fromArray($condition);
                } catch (\Throwable) {
                    return false;
                }

                continue;
            }

            return false;
        }

        return true;
    }

    public function getType(): string
    {
        return self::TYPE_STRING;
    }
}
