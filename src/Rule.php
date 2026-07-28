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

    private ?string $id = null;

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

    public function setId(string $id): self
    {
        $this->id = $id;

        return $this;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

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
     * @param array<string, \Utopia\WAF\Attribute> $types
     */
    public function matches(array $attributes, array $types = []): bool
    {
        foreach ($this->conditions as $condition) {
            if (!$condition->matches($attributes, $types)) {
                return false;
            }
        }

        return true;
    }
}
