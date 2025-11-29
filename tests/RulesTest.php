<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Rules\Allow;
use Utopia\WAF\Rules\Challenge;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\RateLimit;

class RulesTest extends TestCase
{
    public function testAllowRuleMatches(): void
    {
        $rule = new Allow([
            Condition::equal('ip', ['127.0.0.1']),
        ]);

        $this->assertTrue($rule->matches(['ip' => '127.0.0.1']));
        $this->assertSame('allow', $rule->getAction());
    }

    public function testDenyRule(): void
    {
        $rule = new Deny([
            Condition::equal('method', ['POST']),
        ]);

        $this->assertTrue($rule->matches(['method' => 'POST']));
        $this->assertSame('deny', $rule->getAction());
    }

    public function testChallengeRuleTypeDefaults(): void
    {
        $defaultRule = new Challenge();
        $customRule = new Challenge([], Challenge::TYPE_CUSTOM);

        $this->assertSame('challenge', $defaultRule->getAction());
        $this->assertSame(Challenge::TYPE_CAPTCHA, $defaultRule->getType());
        $this->assertSame(Challenge::TYPE_CUSTOM, $customRule->getType());
    }

    public function testRateLimitMetadata(): void
    {
        $rule = new RateLimit([], limit: 10, interval: 600);

        $this->assertSame('rateLimit', $rule->getAction());
        $this->assertSame(10, $rule->getLimit());
        $this->assertSame(600, $rule->getInterval());
    }
}
