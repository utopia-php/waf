<?php

namespace Utopia\WAF\Rules;

use Utopia\WAF\Rule;

class RateLimit extends Rule
{
    private int $limit;

    private int $interval;

    /**
     * @param array<\Utopia\WAF\Condition|array<string, mixed>> $conditions
     */
    public function __construct(
        array $conditions = [],
        int $limit = 100,
        int $interval = 3600
    ) {
        parent::__construct($conditions);
        $this->limit = max(1, $limit);
        $this->interval = max(1, $interval);
    }

    public function getAction(): string
    {
        return self::ACTION_RATE_LIMIT;
    }

    public function getLimit(): int
    {
        return $this->limit;
    }

    public function getInterval(): int
    {
        return $this->interval;
    }
}
