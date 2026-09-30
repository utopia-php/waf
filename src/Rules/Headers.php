<?php

namespace Utopia\WAF\Rules;

use Utopia\WAF\Rule;

/**
 * Carries response headers to add when the rule matches.
 *
 * Unlike the other actions this rule is non-terminal: it does not decide the
 * request, so the firewall records it and keeps evaluating the rules after it.
 */
class Headers extends Rule
{
    /**
     * @var array<string, string>
     */
    private array $headers;

    /**
     * @param array<\Utopia\WAF\Condition|array<string, mixed>> $conditions
     * @param array<string, string> $headers Response headers, keyed by header name.
     */
    public function __construct(array $conditions = [], array $headers = [])
    {
        parent::__construct($conditions);

        if ($headers === []) {
            throw new \InvalidArgumentException('Headers rule requires at least one header.');
        }

        foreach ($headers as $name => $value) {
            if (!\is_string($name) || preg_match('/^[A-Za-z0-9!#$%&\'*+.^_`|~-]+$/', $name) !== 1) {
                throw new \InvalidArgumentException('Invalid header name: ' . $name);
            }

            // Control characters would let a value smuggle in further headers.
            if (!\is_string($value) || preg_match('/[\x00-\x08\x0A-\x1F\x7F]/', $value) === 1) {
                throw new \InvalidArgumentException('Invalid value for header: ' . $name);
            }
        }

        $this->headers = $headers;
    }

    public function getAction(): string
    {
        return self::ACTION_HEADERS;
    }

    public function isTerminal(): bool
    {
        return false;
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }
}
