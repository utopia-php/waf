<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Rule;
use Utopia\WAF\RuleFactory;
use Utopia\WAF\Rules\Bypass;
use Utopia\WAF\Rules\Challenge;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\RateLimit;
use Utopia\WAF\Rules\Redirect;

class RuleFactoryTest extends TestCase
{
    public function testCreatesBypassRule(): void
    {
        $rule = RuleFactory::fromArray([
            'action' => Rule::ACTION_BYPASS,
            'conditions' => [
                Condition::equal('ip', ['127.0.0.1'])->toArray(),
            ],
        ]);

        $this->assertInstanceOf(Bypass::class, $rule);
        $this->assertSame(Rule::ACTION_BYPASS, $rule->getAction());
        $this->assertCount(1, $rule->getConditions());
    }

    public function testCreatesDenyRule(): void
    {
        $rule = RuleFactory::fromArray([
            'action' => Rule::ACTION_DENY,
            'conditions' => [
                Condition::contains('path', ['/admin'])->toArray(),
            ],
        ]);

        $this->assertInstanceOf(Deny::class, $rule);
        $this->assertSame(Rule::ACTION_DENY, $rule->getAction());
    }

    public function testCreatesChallengeRuleWithConfig(): void
    {
        $rule = RuleFactory::fromArray([
            'action' => Rule::ACTION_CHALLENGE,
            'conditions' => [],
            'config' => [
                'type' => Challenge::TYPE_CUSTOM,
            ],
        ]);

        $this->assertInstanceOf(Challenge::class, $rule);
        $this->assertSame(Challenge::TYPE_CUSTOM, $rule->getType());
    }

    public function testCreatesRateLimitRuleWithConfig(): void
    {
        $rule = RuleFactory::fromArray([
            'action' => Rule::ACTION_RATE_LIMIT,
            'conditions' => [],
            'config' => [
                'limit' => 10,
                'interval' => 60,
            ],
        ]);

        $this->assertInstanceOf(RateLimit::class, $rule);
        $this->assertSame(10, $rule->getLimit());
        $this->assertSame(60, $rule->getInterval());
    }

    public function testCreatesRedirectRuleWithConfig(): void
    {
        $rule = RuleFactory::fromArray([
            'action' => Rule::ACTION_REDIRECT,
            'conditions' => [],
            'config' => [
                'location' => '/blocked',
                'statusCode' => 307,
            ],
        ]);

        $this->assertInstanceOf(Redirect::class, $rule);
        $this->assertSame('/blocked', $rule->getLocation());
        $this->assertSame(307, $rule->getStatusCode());
    }

    public function testCreatesRuleFromParameters(): void
    {
        $rule = RuleFactory::create(
            Rule::ACTION_RATE_LIMIT,
            [
                Condition::equal('ip', ['127.0.0.1']),
            ],
            [
                'limit' => 25,
                'interval' => 120,
            ]
        );

        $this->assertInstanceOf(RateLimit::class, $rule);
        $this->assertSame(25, $rule->getLimit());
        $this->assertSame(120, $rule->getInterval());
        $this->assertCount(1, $rule->getConditions());
    }

    public function testUsesRuleDefaults(): void
    {
        $challenge = RuleFactory::fromArray([
            'action' => Rule::ACTION_CHALLENGE,
        ]);
        $rateLimit = RuleFactory::fromArray([
            'action' => Rule::ACTION_RATE_LIMIT,
        ]);
        $redirect = RuleFactory::fromArray([
            'action' => Rule::ACTION_REDIRECT,
        ]);

        $this->assertInstanceOf(Challenge::class, $challenge);
        $this->assertSame(Challenge::TYPE_CAPTCHA, $challenge->getType());

        $this->assertInstanceOf(RateLimit::class, $rateLimit);
        $this->assertSame(100, $rateLimit->getLimit());
        $this->assertSame(3600, $rateLimit->getInterval());

        $this->assertInstanceOf(Redirect::class, $redirect);
        $this->assertSame('/', $redirect->getLocation());
        $this->assertSame(302, $redirect->getStatusCode());
    }

    public function testRejectsUnsupportedAction(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => 'unknown',
        ]);
    }

    public function testRejectsInvalidActionPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => 123,
        ]);
    }

    public function testRejectsNullActionPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => null,
        ]);
    }

    public function testRejectsInvalidConditionsPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => Rule::ACTION_DENY,
            'conditions' => 'invalid',
        ]);
    }

    public function testRejectsNullConditionsPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => Rule::ACTION_DENY,
            'conditions' => null,
        ]);
    }

    public function testRejectsAssociativeConditionsPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => Rule::ACTION_DENY,
            'conditions' => [
                'method' => 'equal',
            ],
        ]);
    }

    public function testRejectsInvalidConditionDefinition(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => Rule::ACTION_DENY,
            'conditions' => [
                [
                    'method' => 'unknown',
                    'values' => [],
                ],
            ],
        ]);
    }

    public function testRejectsInvalidConfigPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => Rule::ACTION_REDIRECT,
            'config' => 'invalid',
        ]);
    }

    public function testRejectsNullConfigPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => Rule::ACTION_REDIRECT,
            'config' => null,
        ]);
    }

    public function testRejectsInvalidConfigValueTypes(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RuleFactory::fromArray([
            'action' => Rule::ACTION_REDIRECT,
            'config' => [
                'statusCode' => '307',
            ],
        ]);
    }
}
