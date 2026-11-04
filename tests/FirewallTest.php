<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Firewall;
use Utopia\WAF\Rules\Bypass;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\RateLimit;
use Utopia\WAF\Schedule;

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

    public function testIpConditionsMatchCidrBlocksByDefault(): void
    {
        $deny = (new Deny([
            Condition::equal('ip', ['10.0.0.0/8']),
        ]))->setId('rule_cidr');

        // The requestIP alias resolves to the ip attribute and its default IP attribute type.
        $firewall = new Firewall();
        $firewall->setAttribute('requestIP', '10.4.20.9');
        $firewall->addRule($deny);

        $this->assertFalse($firewall->verify());
        $this->assertSame('rule_cidr', $firewall->getLastMatchedRule()?->getId());

        $miss = new Firewall();
        $miss->setAttribute('requestIP', '11.0.0.1');
        $miss->addRule($deny);

        $miss->verify();
        $this->assertNull($miss->getLastMatchedRule());
    }

    public function testNotEqualIpConditionExcludesCidrBlock(): void
    {
        $deny = (new Deny([
            Condition::notEqual('ip', '10.0.0.0/8'),
        ]))->setId('rule_outside');

        $inside = new Firewall();
        $inside->setAttribute('ip', '10.4.20.9');
        $inside->addRule($deny);

        $inside->verify();
        $this->assertNull($inside->getLastMatchedRule());

        $outside = new Firewall();
        $outside->setAttribute('ip', '203.0.113.10');
        $outside->addRule($deny);

        $this->assertFalse($outside->verify());
        $this->assertSame('rule_outside', $outside->getLastMatchedRule()?->getId());
    }

    public function testRuleOutsideItsScheduleFallsThroughToTheNextRule(): void
    {
        $nightlyDeny = (new Deny([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setId('nightly_deny')->setSchedule(Schedule::fromArray([
            'mode' => 'daily',
            'startTime' => '22:00',
            'endTime' => '06:00',
        ]));

        $bypass = (new Bypass([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setId('bypass');

        $now = (new \DateTimeImmutable('2026-11-04 12:00', new \DateTimeZone('UTC')))->getTimestamp();

        $firewall = new Firewall();
        $firewall->setAttribute('ip', '127.0.0.1');
        $firewall->setRules([$nightlyDeny, $bypass]);
        $firewall->setClock(static function () use (&$now): int {
            return $now;
        });

        $this->assertTrue($firewall->verify());
        $matchedAtNoon = $firewall->getLastMatchedRule();
        $this->assertNotNull($matchedAtNoon);
        $this->assertSame('bypass', $matchedAtNoon->getId());

        $now = (new \DateTimeImmutable('2026-11-05 01:00', new \DateTimeZone('UTC')))->getTimestamp();

        $this->assertFalse($firewall->verify());
        $matchedAtNight = $firewall->getLastMatchedRule();
        $this->assertNotNull($matchedAtNight);
        $this->assertSame('nightly_deny', $matchedAtNight->getId());
    }

    public function testRuleWithoutScheduleIsAlwaysActive(): void
    {
        $deny = (new Deny([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setId('deny');

        $firewall = new Firewall();
        $firewall->setAttribute('ip', '127.0.0.1');
        $firewall->addRule($deny);

        foreach (['1970-01-01 00:00', '2026-11-07 03:00', '2038-01-19 23:59'] as $utc) {
            $now = (new \DateTimeImmutable($utc, new \DateTimeZone('UTC')))->getTimestamp();
            $firewall->setClock(static fn (): int => $now);

            $this->assertFalse($firewall->verify(), $utc);
            $matched = $firewall->getLastMatchedRule();
            $this->assertNotNull($matched, $utc);
            $this->assertSame('deny', $matched->getId(), $utc);
        }
    }

    public function testClockIsReadOnceSoEveryRuleSeesTheSameMoment(): void
    {
        // Each read is a second later, so a per-rule read would see 17:00:00 for the second rule.
        $reads = 0;
        $start = (new \DateTimeImmutable('2026-11-04 16:59:59', new \DateTimeZone('UTC')))->getTimestamp();
        $clock = static function () use (&$reads, $start): int {
            return $start + $reads++;
        };

        $evening = (new Deny([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setId('evening')->setSchedule(Schedule::fromArray(['mode' => 'daily', 'startTime' => '17:00', 'endTime' => '18:00']));

        $office = (new Bypass([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setId('office')->setSchedule(Schedule::fromArray(['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00']));

        $firewall = new Firewall();
        $firewall->setAttribute('ip', '127.0.0.1');
        $firewall->setRules([$evening, $office]);
        $firewall->setClock($clock);

        $this->assertTrue($firewall->verify());
        $matched = $firewall->getLastMatchedRule();
        $this->assertNotNull($matched);
        $this->assertSame('office', $matched->getId());
        $this->assertSame(1, $reads);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function clockSkews(): iterable
    {
        yield 'one second ahead' => [1];
        yield 'thirty seconds ahead' => [30];
        yield 'forty-five seconds behind' => [-45];
        yield 'two minutes ahead' => [120];
    }

    /**
     * Two servers whose clocks differ by $skew seconds only disagree within $skew of a window edge.
     */
    #[DataProvider('clockSkews')]
    public function testSkewedServersDisagreeOnlyNearAWindowEdge(int $skew): void
    {
        $schedule = Schedule::fromArray(['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00']);
        $close = (new \DateTimeImmutable('2026-11-04 17:00', new \DateTimeZone('UTC')))->getTimestamp();

        $disagreements = [];
        for ($t = $close - 300; $t <= $close + 300; $t++) {
            if ($this->deniesAt($schedule, $t) !== $this->deniesAt($schedule, $t + $skew)) {
                $disagreements[] = $t;
            }
        }

        $this->assertCount(\abs($skew), $disagreements);
        foreach ($disagreements as $t) {
            $this->assertLessThanOrEqual(\abs($skew), \abs($close - $t), 'disagreement far from the edge at ' . \gmdate('H:i:s', $t));
        }
    }

    public function testClockSteppingBackwardsIsJudgedOnTheNewTimeAlone(): void
    {
        $schedule = Schedule::fromArray(['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00']);
        $close = (new \DateTimeImmutable('2026-11-04 17:00', new \DateTimeZone('UTC')))->getTimestamp();

        $now = $close;
        $deny = (new Deny([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setSchedule($schedule);

        $firewall = new Firewall();
        $firewall->setAttribute('ip', '127.0.0.1');
        $firewall->addRule($deny);
        $firewall->setClock(static function () use (&$now): int {
            return $now;
        });

        $firewall->verify();
        $this->assertNull($firewall->getLastMatchedRule(), 'closed at 17:00:00');

        $now = $close - 1; // the clock is corrected backwards by a second
        $firewall->verify();
        $this->assertSame($deny, $firewall->getLastMatchedRule(), 'open again at 16:59:59');

        $now = $close + 3600; // and jumps forward an hour
        $firewall->verify();
        $this->assertNull($firewall->getLastMatchedRule(), 'closed at 18:00:00');
    }

    public function testWithoutAClockTheCurrentTimeIsUsed(): void
    {
        // Exactly one of these is active at any moment: today's weekday, or every other day.
        do {
            $before = \time();
            $today = (int) \gmdate('N', $before);
            $otherDays = \array_values(\array_diff(\range(1, 7), [$today]));

            $todayOnly = (new Deny([Condition::equal('ip', ['127.0.0.1'])]))
                ->setId('today')->setSchedule(Schedule::fromArray(['mode' => 'weekly', 'days' => [$today]]));
            $otherDaysOnly = (new Deny([Condition::equal('ip', ['127.0.0.1'])]))
                ->setId('other')->setSchedule(Schedule::fromArray(['mode' => 'weekly', 'days' => $otherDays]));

            $firewall = new Firewall();
            $firewall->setAttribute('ip', '127.0.0.1');
            $firewall->setRules([$otherDaysOnly, $todayOnly]);
            $firewall->verify();
            $after = \time();
        } while (\gmdate('N', $before) !== \gmdate('N', $after)); // ran across midnight UTC: retry

        $matched = $firewall->getLastMatchedRule();
        $this->assertNotNull($matched);
        $this->assertSame('today', $matched->getId());
    }

    private function deniesAt(Schedule $schedule, int $timestamp): bool
    {
        $firewall = new Firewall();
        $firewall->setAttribute('ip', '127.0.0.1');
        $firewall->addRule((new Deny([Condition::equal('ip', ['127.0.0.1'])]))->setSchedule($schedule));
        $firewall->setClock(static fn (): int => $timestamp);
        $firewall->verify();

        return $firewall->getLastMatchedRule() !== null;
    }

    public function testNoMatchWhenEveryRuleIsOutsideItsSchedule(): void
    {
        $weekendDeny = (new Deny([
            Condition::equal('ip', ['127.0.0.1']),
        ]))->setSchedule(Schedule::fromArray(['mode' => 'weekends']));

        $monday = (new \DateTimeImmutable('2026-11-02 12:00', new \DateTimeZone('UTC')))->getTimestamp();

        $firewall = new Firewall();
        $firewall->setAttribute('ip', '127.0.0.1');
        $firewall->addRule($weekendDeny);
        $firewall->setClock(static fn (): int => $monday);

        $this->assertFalse($firewall->verify());
        $this->assertNull($firewall->getLastMatchedRule());
    }
}
