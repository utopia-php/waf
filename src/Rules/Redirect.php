<?php

namespace Utopia\WAF\Rules;

use Utopia\WAF\Rule;

class Redirect extends Rule
{
    private string $location;

    private int $statusCode;

    /**
     * @param array<\Utopia\WAF\Condition|array<string, mixed>> $conditions
     */
    public function __construct(array $conditions = [], string $location = '/', int $statusCode = 302)
    {
        parent::__construct($conditions);
        $this->location = $location;
        $this->statusCode = $statusCode;
    }

    public function getAction(): string
    {
        return self::ACTION_REDIRECT;
    }

    public function getLocation(): string
    {
        return $this->location;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}
