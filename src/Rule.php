<?php

namespace Utopia\WAF;

abstract class Rule
{
    public const ACTION_BYPASS = 'bypass';
    public const ACTION_DENY = 'deny';
    public const ACTION_CHALLENGE = 'challenge';
    public const ACTION_RATE_LIMIT = 'rateLimit';
    public const ACTION_REDIRECT = 'redirect';

    /**
     * @var array<Condition>
     */
    protected array $conditions = [];

    /**
     * @param array<Condition|array<string, mixed>> $conditions
     */
    public function __construct(array $conditions = [])
    {
        $this->conditions = array_map(
            static function (Condition|array $condition): Condition {
                if ($condition instanceof Condition) {
                    return clone $condition;
                }

                return Condition::fromArray($condition);
            },
            $conditions
        );
    }

    abstract public function getAction(): string;

    /**
     * @return array<Condition>
     */
    public function getConditions(): array
    {
        return $this->conditions;
    }

    public function addCondition(Condition $condition): self
    {
        $this->conditions[] = $condition;

        return $this;
    }

    /**
     * Evaluate rule conditions against provided attributes.
     *
     * @param array<string, mixed> $attributes
     */
    public function matches(array $attributes): bool
    {
        foreach ($this->conditions as $condition) {
            if (!$condition->matches($attributes)) {
                return false;
            }
        }

        return true;
    }
}
