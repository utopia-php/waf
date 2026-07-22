<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Firewall;
use Utopia\WAF\Rules\Bypass;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\RateLimit;

class FirewallTest extends TestCase
{
    public function testVerifyUsesPopulatedRequestAttributesAndExposesMatchedRule(): void
    {
        $firewall = new Firewall();
        $firewall->setAttributes([
            'requestIP' => '127.0.0.1',
            'requestPath' => '/v1/locale',
            'requestCountry' => 'IL',
        ]);

        $deny = new Deny([
            Condition::equal('ip', ['127.0.0.1']),
            Condition::contains('path', ['/v1']),
            Condition::equal('country', ['IL']),
        ]);

        $firewall->addRule($deny);

        $this->assertFalse($firewall->verify());
        $this->assertSame($deny, $firewall->getLastMatchedRule());

        $firewall->clearRules();
        $firewall->addRule(new Deny([
            Condition::equal('country', ['US']),
        ]));

        $this->assertFalse($firewall->verify());
        $this->assertNull($firewall->getLastMatchedRule());
    }

    public function testVerifyDeniesRequestsInsideCidrBlock(): void
    {
        $firewall = new Firewall();
        $firewall->setAttribute('requestIP', '203.0.113.5');

        $deny = new Deny([
            Condition::inCidr('ip', ['203.0.113.0/24', '2001:db8::/32']),
        ]);

        $firewall->addRule($deny);

        $this->assertFalse($firewall->verify());
        $this->assertSame($deny, $firewall->getLastMatchedRule());

        $firewall->setAttribute('requestIP', '198.51.100.5');

        $this->assertFalse($firewall->verify(), 'No rule should match an address outside the block');
        $this->assertNull($firewall->getLastMatchedRule());
    }

    public function testRuleOrder(): void
    {
        $firewall = new Firewall();
        $firewall->setAttribute('requestIP', '127.0.0.1');
        $firewall->setAttribute('requestPath', '/index');

        $deny = new Deny([
            Condition::equal('ip', ['127.0.0.1']),
            Condition::notEqual('path', '/health'),
        ]);

        $bypass = new Bypass([
            Condition::equal('ip', ['127.0.0.1']),
        ]);

        $firewall->addRule($deny);
        $firewall->addRule($bypass);

        $this->assertFalse($firewall->verify(), 'Deny should be executed first');

        $firewall->clearRules();
        $firewall->addRule($bypass);
        $firewall->addRule($deny);

        $this->assertTrue($firewall->verify(), 'Bypass should pass when it is the first matching rule');
    }

    public function testRateLimitMetadata(): void
    {
        $firewall = new Firewall();
        $firewall->setAttributes([
            'requestIP' => '192.168.1.10',
            'requestPath' => '/api',
        ]);

        $rateLimit = new RateLimit([
            Condition::equal('ip', ['192.168.1.10']),
        ], limit: 2, interval: 60);

        $firewall->addRule($rateLimit);

        $this->assertTrue($firewall->verify());
        $matched = $firewall->getLastMatchedRule();

        $this->assertInstanceOf(RateLimit::class, $matched);
        if (!$matched instanceof RateLimit) {
            return;
        }

        $this->assertSame(2, $matched->getLimit());
        $this->assertSame(60, $matched->getInterval());
    }

    public function testRuleIdentifierRoundTrip(): void
    {
        $rule = (new Deny([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setId('rule_abc');

        $firewall = new Firewall();
        $firewall->setAttribute('requestIP', '127.0.0.1');
        $firewall->addRule($rule);

        $this->assertFalse($firewall->verify());
        $this->assertSame('rule_abc', $firewall->getLastMatchedRule()?->getId());
    }
}
