<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Rules\Bypass;
use Utopia\WAF\Rules\Challenge;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\Headers;
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
        $computeRule = new Challenge([], Challenge::TYPE_COMPUTE);

        $this->assertSame('challenge', $defaultRule->getAction());
        $this->assertSame(Challenge::TYPE_CAPTCHA, $defaultRule->getType());
        $this->assertSame(Challenge::TYPE_CUSTOM, $customRule->getType());
        $this->assertSame(Challenge::TYPE_COMPUTE, $computeRule->getType());
    }

    public function testChallengeRuleRejectsUnknownType(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Challenge([], 'not-a-real-type');
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

    public function testHeadersRule(): void
    {
        $rule = new Headers([
            Condition::startsWith('path', '/api'),
        ], headers: ['X-Frame-Options' => 'DENY']);

        $this->assertTrue($rule->matches(['path' => '/api/users']));
        $this->assertSame('headers', $rule->getAction());
        $this->assertSame(['X-Frame-Options' => 'DENY'], $rule->getHeaders());
        $this->assertFalse($rule->isTerminal());
        $this->assertTrue((new Deny())->isTerminal());
    }

    public function testHeadersRuleRejectsEmptyHeaders(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Headers([], headers: []);
    }

    public function testHeadersRuleRejectsInvalidName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Headers([], headers: ['X Frame: Options' => 'DENY']);
    }

    public function testHeadersRuleRejectsLineBreaksInValue(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Headers([], headers: ['X-Frame-Options' => "DENY\r\nSet-Cookie: session=1"]);
    }
}
