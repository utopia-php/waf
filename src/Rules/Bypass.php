<?php

namespace Utopia\WAF\Rules;

use Utopia\WAF\Rule;

class Bypass extends Rule
{
    public function getAction(): string
    {
        return self::ACTION_BYPASS;
    }
}
