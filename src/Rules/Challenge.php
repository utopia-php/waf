<?php

namespace Utopia\WAF\Rules;

use Utopia\WAF\Rule;

class Challenge extends Rule
{
    public const TYPE_CAPTCHA = 'captcha';
    public const TYPE_CUSTOM = 'custom';

    private string $type;

    /**
     * @param array<\Utopia\WAF\Condition|array<string, mixed>> $conditions
     */
    public function __construct(array $conditions = [], string $type = self::TYPE_CAPTCHA)
    {
        parent::__construct($conditions);
        if (!in_array($type, [self::TYPE_CAPTCHA, self::TYPE_CUSTOM], true)) {
            throw new \InvalidArgumentException('Invalid challenge type: ' . $type);
        }
        $this->type = $type;
    }

    public function getAction(): string
    {
        return self::ACTION_CHALLENGE;
    }

    public function getType(): string
    {
        return $this->type;
    }
}
