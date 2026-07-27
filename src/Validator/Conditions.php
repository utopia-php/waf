<?php

namespace Utopia\WAF\Validator;

use Utopia\Validator;
use Utopia\WAF\Condition;
use Utopia\WAF\Firewall;
use Utopia\WAF\Attribute;

class Conditions extends Validator
{
    /**
     * @var array<string, Attribute>
     */
    private array $attributeTypes = [];

    /**
     * @param array<string, Attribute> $attributeTypes typed value validation, keyed by attribute name
     */
    public function __construct(
        private int $maxConditions = 100,
        private int $maxPayloadLength = 4096,
        array $attributeTypes = []
    ) {
        foreach ($attributeTypes as $attribute => $type) {
            $this->attributeTypes[Firewall::normalizeAttributeName($attribute)] = $type;
        }
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
            if (!\is_array($condition) && !\is_string($condition)) {
                return false;
            }

            if (!$this->isValidCondition($condition, $count)) {
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
     * @param array<string, mixed>|string $payload
     */
    private function isValidCondition(array|string $payload, int &$count): bool
    {
        if (\is_string($payload)) {
            if ($this->maxPayloadLength > 0 && \strlen($payload) > $this->maxPayloadLength) {
                return false;
            }

            try {
                $payload = Condition::decode($payload)->toArray();
            } catch (\Throwable) {
                return false;
            }
        }

        $count++;

        if ($this->maxConditions > 0 && $count > $this->maxConditions) {
            return false;
        }

        if ($this->maxPayloadLength > 0 && !$this->isWithinPayloadLimit($payload)) {
            return false;
        }

        $method = $payload['method'] ?? '';
        $values = $payload['values'] ?? [];

        if (!$this->hasValidTypedValues($payload)) {
            return false;
        }

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
    private function hasValidTypedValues(array $payload): bool
    {
        if ($this->attributeTypes === []) {
            return true;
        }

        $method = $payload['method'] ?? '';
        $attribute = $payload['attribute'] ?? '';
        $values = $payload['values'] ?? [];

        if (!\is_string($method) || !\is_string($attribute) || !\is_array($values)) {
            return true; // structural validity is enforced by Condition::fromArray()
        }

        if (\in_array($method, [Condition::TYPE_AND, Condition::TYPE_OR], true)) {
            return true; // nested conditions are validated recursively
        }

        $type = $this->attributeTypes[Firewall::normalizeAttributeName($attribute)] ?? null;
        if ($type === null) {
            return true;
        }

        foreach ($values as $value) {
            if ($type->validateValue($method, $value) !== null) {
                return false;
            }
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
