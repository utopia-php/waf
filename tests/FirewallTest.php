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
}
