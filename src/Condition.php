<?php

namespace Utopia\WAF;

use JsonException;
use Utopia\WAF\Exception\Condition as ConditionException;

/**
 * Condition
 *
 * Inspired by Utopia\Database\Query with a pared-down list of operators geared towards WAF rules.
 */
class Condition
{
    // Comparison operators.
    public const TYPE_EQUAL = 'equal';
    public const TYPE_NOT_EQUAL = 'notEqual';
    public const TYPE_LESS_THAN = 'lessThan';
    public const TYPE_LESS_THAN_EQUAL = 'lessThanEqual';
    public const TYPE_GREATER_THAN = 'greaterThan';
    public const TYPE_GREATER_THAN_EQUAL = 'greaterThanEqual';
    public const TYPE_BETWEEN = 'between';
    public const TYPE_NOT_BETWEEN = 'notBetween';

    // String helpers.
    public const TYPE_CONTAINS = 'contains';
    public const TYPE_NOT_CONTAINS = 'notContains';
    public const TYPE_STARTS_WITH = 'startsWith';
    public const TYPE_NOT_STARTS_WITH = 'notStartsWith';
    public const TYPE_ENDS_WITH = 'endsWith';
    public const TYPE_NOT_ENDS_WITH = 'notEndsWith';

    // Null helpers.
    public const TYPE_IS_NULL = 'isNull';
    public const TYPE_IS_NOT_NULL = 'isNotNull';

    // Logical operators.
    public const TYPE_AND = 'and';
    public const TYPE_OR = 'or';

    private const LOGICAL_TYPES = [
        self::TYPE_AND,
        self::TYPE_OR,
    ];

    /**
     * @var array<string>
     */
    private const TYPES = [
        self::TYPE_EQUAL,
        self::TYPE_NOT_EQUAL,
        self::TYPE_LESS_THAN,
        self::TYPE_LESS_THAN_EQUAL,
        self::TYPE_GREATER_THAN,
        self::TYPE_GREATER_THAN_EQUAL,
        self::TYPE_BETWEEN,
        self::TYPE_NOT_BETWEEN,
        self::TYPE_CONTAINS,
        self::TYPE_NOT_CONTAINS,
        self::TYPE_STARTS_WITH,
        self::TYPE_NOT_STARTS_WITH,
        self::TYPE_ENDS_WITH,
        self::TYPE_NOT_ENDS_WITH,
        self::TYPE_IS_NULL,
        self::TYPE_IS_NOT_NULL,
        self::TYPE_AND,
        self::TYPE_OR,
    ];

    private string $method;

    private string $attribute;

    /**
     * @var array<mixed>
     */
    private array $values;

    /**
     * @param array<mixed> $values
     */
    public function __construct(string $method, string $attribute = '', array $values = [])
    {
        if (!self::isMethod($method)) {
            throw new ConditionException("Unsupported condition method: {$method}");
        }

        $this->method = $method;
        $this->attribute = $attribute;
        $this->values = $this->normalizeValues($values);
    }

    public function __clone(): void
    {
        foreach ($this->values as $index => $value) {
            if ($value instanceof self) {
                $this->values[$index] = clone $value;
            }
        }
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getAttribute(): string
    {
        return $this->attribute;
    }

    /**
     * @return array<mixed>
     */
    public function getValues(): array
    {
        return $this->values;
    }

    public function isLogical(): bool
    {
        return \in_array($this->method, self::LOGICAL_TYPES, true);
    }

    public static function isMethod(string $value): bool
    {
        return \in_array($value, self::TYPES, true);
    }

    /**
     * Parses a JSON encoded condition.
     */
    public static function parse(string $payload): self
    {
        try {
            $decoded = \json_decode($payload, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new ConditionException('Invalid condition payload: ' . $exception->getMessage());
        }

        if (!\is_array($decoded)) {
            throw new ConditionException('Invalid condition payload. Expecting array definition.');
        }

        return self::fromArray($decoded);
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        $method = $payload['method'] ?? '';
        $attribute = $payload['attribute'] ?? '';
        $values = $payload['values'] ?? [];

        if (!\is_string($method)) {
            throw new ConditionException('Invalid condition method definition.');
        }

        if (!\is_string($attribute)) {
            throw new ConditionException('Invalid condition attribute definition.');
        }

        if (!\is_array($values)) {
            throw new ConditionException('Invalid condition values definition.');
        }

        if (\in_array($method, self::LOGICAL_TYPES, true)) {
            $values = array_map(
                static function (mixed $value): self {
                    if (!\is_array($value)) {
                        throw new ConditionException('Invalid nested condition definition.');
                    }

                    return self::fromArray($value);
                },
                $values
            );
        }

        return new self($method, $attribute, $values);
    }

    /**
     * @param array<array<string, mixed>> $conditions
     * @return array<self>
     */
    public static function fromArrays(array $conditions): array
    {
        return array_map(static fn (array $condition): self => self::fromArray($condition), $conditions);
    }

    public function toArray(): array
    {
        $result = ['method' => $this->method];

        if ($this->attribute !== '') {
            $result['attribute'] = $this->attribute;
        }

        if ($this->isLogical()) {
            $result['values'] = array_map(
                static fn (self $condition): array => $condition->toArray(),
                $this->values
            );
        } else {
            $result['values'] = $this->values;
        }

        return $result;
    }

    /**
     * Encode condition as JSON string.
     *
     * @throws ConditionException
     */
    public function toString(): string
    {
        try {
            return \json_encode($this->toArray(), flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new ConditionException('Unable to encode condition: ' . $exception->getMessage());
        }
    }

    /**
     * @param array<mixed> $values
     */
    public static function equal(string $attribute, array $values): self
    {
        return new self(self::TYPE_EQUAL, $attribute, $values);
    }

    public static function notEqual(string $attribute, string|int|float|bool $value): self
    {
        return new self(self::TYPE_NOT_EQUAL, $attribute, [$value]);
    }

    public static function lessThan(string $attribute, string|int|float $value): self
    {
        return new self(self::TYPE_LESS_THAN, $attribute, [$value]);
    }

    public static function lessThanEqual(string $attribute, string|int|float $value): self
    {
        return new self(self::TYPE_LESS_THAN_EQUAL, $attribute, [$value]);
    }

    public static function greaterThan(string $attribute, string|int|float $value): self
    {
        return new self(self::TYPE_GREATER_THAN, $attribute, [$value]);
    }

    public static function greaterThanEqual(string $attribute, string|int|float $value): self
    {
        return new self(self::TYPE_GREATER_THAN_EQUAL, $attribute, [$value]);
    }

    public static function contains(string $attribute, array $values): self
    {
        return new self(self::TYPE_CONTAINS, $attribute, $values);
    }

    public static function notContains(string $attribute, array $values): self
    {
        return new self(self::TYPE_NOT_CONTAINS, $attribute, $values);
    }

    public static function between(string $attribute, string|int|float $start, string|int|float $end): self
    {
        return new self(self::TYPE_BETWEEN, $attribute, [$start, $end]);
    }

    public static function notBetween(string $attribute, string|int|float $start, string|int|float $end): self
    {
        return new self(self::TYPE_NOT_BETWEEN, $attribute, [$start, $end]);
    }

    public static function startsWith(string $attribute, string $value): self
    {
        return new self(self::TYPE_STARTS_WITH, $attribute, [$value]);
    }

    public static function notStartsWith(string $attribute, string $value): self
    {
        return new self(self::TYPE_NOT_STARTS_WITH, $attribute, [$value]);
    }

    public static function endsWith(string $attribute, string $value): self
    {
        return new self(self::TYPE_ENDS_WITH, $attribute, [$value]);
    }

    public static function notEndsWith(string $attribute, string $value): self
    {
        return new self(self::TYPE_NOT_ENDS_WITH, $attribute, [$value]);
    }

    public static function isNull(string $attribute): self
    {
        return new self(self::TYPE_IS_NULL, $attribute);
    }

    public static function isNotNull(string $attribute): self
    {
        return new self(self::TYPE_IS_NOT_NULL, $attribute);
    }

    /**
     * @param array<Condition> $conditions
     */
    public static function and(array $conditions): self
    {
        return new self(self::TYPE_AND, '', $conditions);
    }

    /**
     * @param array<Condition> $conditions
     */
    public static function or(array $conditions): self
    {
        return new self(self::TYPE_OR, '', $conditions);
    }

    /**
     * Evaluate the condition against resolved attributes.
     *
     * @param array<string, mixed> $attributes
     */
    public function matches(array $attributes): bool
    {
        if ($this->isLogical()) {
            return $this->matchesLogical($attributes);
        }

        $value = $this->resolveValue($attributes);

        return match ($this->method) {
            self::TYPE_EQUAL => $this->matchesEqual($value),
            self::TYPE_NOT_EQUAL => !$this->matchesEqual($value),
            self::TYPE_LESS_THAN => $this->matchesRelational($value, $this->values[0] ?? null, static fn (int $result): bool => $result < 0),
            self::TYPE_LESS_THAN_EQUAL => $this->matchesRelational($value, $this->values[0] ?? null, static fn (int $result): bool => $result <= 0),
            self::TYPE_GREATER_THAN => $this->matchesRelational($value, $this->values[0] ?? null, static fn (int $result): bool => $result > 0),
            self::TYPE_GREATER_THAN_EQUAL => $this->matchesRelational($value, $this->values[0] ?? null, static fn (int $result): bool => $result >= 0),
            self::TYPE_CONTAINS => $this->matchesContains($value, $this->values),
            self::TYPE_NOT_CONTAINS => !$this->matchesContains($value, $this->values),
            self::TYPE_BETWEEN => $this->matchesRange($value, true),
            self::TYPE_NOT_BETWEEN => !$this->matchesRange($value, true),
            self::TYPE_STARTS_WITH => $this->matchesPrefix($value),
            self::TYPE_NOT_STARTS_WITH => !$this->matchesPrefix($value),
            self::TYPE_ENDS_WITH => $this->matchesSuffix($value),
            self::TYPE_NOT_ENDS_WITH => !$this->matchesSuffix($value),
            self::TYPE_IS_NULL => $value === null,
            self::TYPE_IS_NOT_NULL => $value !== null,
            default => false,
        };
    }

    /**
     * @param array<mixed> $values
     * @return array<mixed>
     */
    private function normalizeValues(array $values): array
    {
        if (!$this->isLogical()) {
            return $values;
        }

        return array_map(static function (mixed $value): self {
            if ($value instanceof self) {
                return $value;
            }

            if (!\is_array($value)) {
                throw new ConditionException('Logical conditions require nested condition definitions.');
            }

            return self::fromArray($value);
        }, $values);
    }

    /**
     * @param array<string, mixed> $attributes
     */
    private function matchesLogical(array $attributes): bool
    {
        if ($this->method === self::TYPE_AND) {
            foreach ($this->values as $condition) {
                if (!$condition->matches($attributes)) {
                    return false;
                }
            }

            return true;
        }

        foreach ($this->values as $condition) {
            if ($condition->matches($attributes)) {
                return true;
            }
        }

        return false;
    }

    private function matchesEqual(mixed $value): bool
    {
        foreach ($this->values as $expected) {
            if ($expected === $value) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<mixed> $needles
     */
    private function matchesContains(mixed $value, array $needles): bool
    {
        if (\is_array($value)) {
            return \count(array_intersect($value, $needles)) > 0;
        }

        if (\is_string($value)) {
            foreach ($needles as $needle) {
                if (\is_string($needle) && $needle !== '' && str_contains($value, $needle)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function matchesRange(mixed $value, bool $inclusive): bool
    {
        if (\count($this->values) < 2) {
            return false;
        }

        [$start, $end] = $this->values;

        if ($value === null || $start === null || $end === null) {
            return false;
        }

        $startComparison = $this->compare($value, $start);
        $endComparison = $this->compare($value, $end);

        if ($startComparison === null || $endComparison === null) {
            return false;
        }

        return $inclusive
            ? $startComparison >= 0 && $endComparison <= 0
            : $startComparison > 0 && $endComparison < 0;
    }

    private function matchesPrefix(mixed $value): bool
    {
        $prefix = $this->values[0] ?? null;

        if (!\is_string($value) || !\is_string($prefix)) {
            return false;
        }

        return str_starts_with($value, $prefix);
    }

    private function matchesSuffix(mixed $value): bool
    {
        $suffix = $this->values[0] ?? null;

        if (!\is_string($value) || !\is_string($suffix)) {
            return false;
        }

        return str_ends_with($value, $suffix);
    }

    /**
     * @param array<string, mixed> $attributes
     */
    private function resolveValue(array $attributes): mixed
    {
        if ($this->attribute === '') {
            return null;
        }

        if (array_key_exists($this->attribute, $attributes)) {
            return $attributes[$this->attribute];
        }

        if (str_contains($this->attribute, '.')) {
            $segments = explode('.', $this->attribute);
            $current = $attributes;

            foreach ($segments as $segment) {
                if (\is_array($current) && array_key_exists($segment, $current)) {
                    $current = $current[$segment];
                    continue;
                }

                return null;
            }

            return $current;
        }

        return $attributes[$this->attribute] ?? null;
    }

    private function compare(mixed $left, mixed $right): ?int
    {
        if ($left === null && $right === null) {
            return 0;
        }

        if ($left === null || $right === null) {
            return null;
        }

        if (\is_numeric($left) && \is_numeric($right)) {
            return $left <=> $right;
        }

        if (\is_string($left) && \is_string($right)) {
            return $left <=> $right;
        }

        if (\is_bool($left) && \is_bool($right)) {
            return $left <=> $right;
        }

        return null;
    }

    /**
     * @param callable(int):bool $verdict
     */
    private function matchesRelational(mixed $value, mixed $reference, callable $verdict): bool
    {
        if ($value === null || $reference === null) {
            return false;
        }

        $result = $this->compare($value, $reference);

        if ($result === null) {
            return false;
        }

        return $verdict($result);
    }
}
