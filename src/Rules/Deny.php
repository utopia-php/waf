<?php

namespace Utopia\WAF\Rules;

use Utopia\WAF\Rule;

class Deny extends Rule
{
    public function getAction(): string
    {
        return self::ACTION_DENY;
    }
}
