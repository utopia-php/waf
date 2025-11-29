<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Rules\Bypass;
use Utopia\WAF\Rules\Challenge;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\RateLimit;
use Utopia\WAF\Rules\Redirect;

class RulesTest extends TestCase
{
    public function testBypassRuleMatches(): void
    {
        $rule = new Bypass([
            Condition::equal('ip', ['127.0.0.1']),
        ]);

        $this->assertTrue($rule->matches(['ip' => '127.0.0.1']));
        $this->assertSame('bypass', $rule->getAction());
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

    public function testRedirectRule(): void
    {
        $rule = new Redirect([], location: '/new', statusCode: 301);

        $this->assertSame('redirect', $rule->getAction());
        $this->assertSame('/new', $rule->getLocation());
        $this->assertSame(301, $rule->getStatusCode());
    }
}
