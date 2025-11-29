<?php

namespace Utopia\WAF\Rules;

use Utopia\WAF\Rule;

class Allow extends Rule
{
    public function getAction(): string
    {
        return self::ACTION_ALLOW;
    }
}
