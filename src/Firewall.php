<?php

namespace Utopia\WAF;

class Firewall
{
    /**
     * @var array<string, mixed>
     */
    private array $attributes = [];

    /**
     * @var array<Rule>
     */
    private array $rules = [];

    private ?Rule $lastMatchedRule = null;

    public function setAttribute(string $name, mixed $value): self
    {
        foreach ($this->attributeAliases($name) as $key) {
            $this->attributes[$key] = $value;
        }

        return $this;
    }

    /**
     * @param array<string, mixed> $attributes
     */
    public function setAttributes(array $attributes): self
    {
        foreach ($attributes as $name => $value) {
            $this->setAttribute($name, $value);
        }

        return $this;
    }

    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }

    public function addRule(Rule $rule): self
    {
        $this->rules[] = $rule;

        return $this;
    }

    /**
     * @param array<Rule> $rules
     */
    public function setRules(array $rules): self
    {
        $this->rules = $rules;

        return $this;
    }

    /**
     * @return array<Rule>
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    public function clearRules(): self
    {
        $this->rules = [];

        return $this;
    }

    public function getLastMatchedRule(): ?Rule
    {
        return $this->lastMatchedRule;
    }

    /**
     * Evaluate the registered rules and return true when the request should be allowed.
     */
    public function verify(): bool
    {
        $this->lastMatchedRule = null;

        foreach ($this->rules as $rule) {
            if (!$rule->matches($this->attributes)) {
                continue;
            }

            $this->lastMatchedRule = $rule;

            return $this->applyRule($rule);
        }

        return false;
    }

    private function applyRule(Rule $rule): bool
    {
        return match ($rule->getAction()) {
            Rule::ACTION_ALLOW => true,
            Rule::ACTION_DENY => false,
            Rule::ACTION_CHALLENGE => false,
            Rule::ACTION_RATE_LIMIT => true,
            Rule::ACTION_REDIRECT => false,
            default => false,
        };
    }

    /**
     * @return array<string>
     */
    private function attributeAliases(string $name): array
    {
        $aliases = [$name];

        $normalized = $this->normalizeRequestKey($name);
        if ($normalized !== $name) {
            $aliases[] = $normalized;
        }

        $lower = strtolower($normalized);
        if (!\in_array($lower, $aliases, true)) {
            $aliases[] = $lower;
        }

        return array_unique($aliases);
    }

    private function normalizeRequestKey(string $name): string
    {
        if (stripos($name, 'request') === 0) {
            $withoutPrefix = substr($name, 7);
            if ($withoutPrefix !== false && $withoutPrefix !== '') {
                return lcfirst($withoutPrefix);
            }
        }

        return $name;
    }
}
