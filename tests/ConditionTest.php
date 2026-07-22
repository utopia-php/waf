<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Exception\Condition as ConditionException;

class ConditionTest extends TestCase
{
    public function testEqualityOperators(): void
    {
        $equal = Condition::equal('ip', ['127.0.0.1', '10.0.0.1']);
        $notEqual = Condition::notEqual('method', 'POST');

        $this->assertTrue($equal->matches(['ip' => '127.0.0.1']));
        $this->assertFalse($equal->matches(['ip' => '1.1.1.1']));

        $this->assertTrue($notEqual->matches(['method' => 'GET']));
        $this->assertFalse($notEqual->matches(['method' => 'POST']));
    }

    public function testComparisonOperators(): void
    {
        $lessThan = Condition::lessThan('count', 10);
        $lessThanEqual = Condition::lessThanEqual('count', 10);
        $greaterThan = Condition::greaterThan('count', 5);
        $greaterThanEqual = Condition::greaterThanEqual('count', 5);

        $this->assertTrue($lessThan->matches(['count' => 9]));
        $this->assertFalse($lessThan->matches(['count' => 10]));

        $this->assertTrue($lessThanEqual->matches(['count' => 10]));
        $this->assertTrue($greaterThan->matches(['count' => 6]));
        $this->assertFalse($greaterThan->matches(['count' => 5]));
        $this->assertTrue($greaterThanEqual->matches(['count' => 5]));
    }

    public function testContainsOperators(): void
    {
        $stringContains = Condition::contains('path', ['admin', 'dashboard']);
        $arrayContains = Condition::contains('tags', ['security']);
        $notContains = Condition::notContains('path', ['forbidden']);

        $this->assertTrue($stringContains->matches(['path' => '/admin/users']));
        $this->assertFalse($stringContains->matches(['path' => '/public']));

        $this->assertTrue($arrayContains->matches(['tags' => ['security', 'waf']]));
        $this->assertFalse($arrayContains->matches(['tags' => ['network']]));

        $this->assertTrue($notContains->matches(['path' => '/allowed']));
        $this->assertFalse($notContains->matches(['path' => '/forbidden']));
    }

    public function testRangeOperators(): void
    {
        $between = Condition::between('latency', 100, 200);
        $notBetween = Condition::notBetween('latency', 100, 200);

        $this->assertTrue($between->matches(['latency' => 150]));
        $this->assertTrue($notBetween->matches(['latency' => 50]));
        $this->assertFalse($notBetween->matches(['latency' => 150]));
    }

    public function testRelationalOperatorsWithNullValues(): void
    {
        $lessThan = Condition::lessThan('count', 5);
        $greaterThan = Condition::greaterThan('count', 5);
        $between = Condition::between('count', 1, 10);

        $this->assertFalse($lessThan->matches(['count' => null]));
        $this->assertFalse($lessThan->matches([]));

        $this->assertFalse($greaterThan->matches(['count' => null]));
        $this->assertFalse($greaterThan->matches([]));

        $this->assertFalse($between->matches(['count' => null]));
        $this->assertFalse($between->matches([]));
    }

    public function testStartsAndEndsOperators(): void
    {
        $startsWith = Condition::startsWith('path', '/api');
        $notStartsWith = Condition::notStartsWith('path', '/admin');
        $endsWith = Condition::endsWith('path', '.json');
        $notEndsWith = Condition::notEndsWith('path', '.php');

        $this->assertTrue($startsWith->matches(['path' => '/api/v1']));
        $this->assertFalse($startsWith->matches(['path' => '/web']));

        $this->assertTrue($notStartsWith->matches(['path' => '/public']));
        $this->assertFalse($notStartsWith->matches(['path' => '/admin']));

        $this->assertTrue($endsWith->matches(['path' => '/status.json']));
        $this->assertFalse($endsWith->matches(['path' => '/status.xml']));

        $this->assertTrue($notEndsWith->matches(['path' => '/status']));
        $this->assertFalse($notEndsWith->matches(['path' => '/index.php']));
    }

    public function testInCidrIpv4Membership(): void
    {
        $inCidr = Condition::inCidr('ip', ['203.0.113.0/24']);

        $this->assertTrue($inCidr->matches(['ip' => '203.0.113.5']));
        $this->assertFalse($inCidr->matches(['ip' => '203.0.114.5']));
    }

    public function testInCidrIpv6Membership(): void
    {
        $inCidr = Condition::inCidr('ip', ['2001:db8::/32']);

        $this->assertTrue($inCidr->matches(['ip' => '2001:db8::1']));
        $this->assertFalse($inCidr->matches(['ip' => '2001:db9::1']));
    }

    public function testInCidrMatchesAnyBlockInList(): void
    {
        $inCidr = Condition::inCidr('ip', ['10.0.0.0/8', '203.0.113.0/24']);

        $this->assertTrue($inCidr->matches(['ip' => '10.5.5.5']));
        $this->assertTrue($inCidr->matches(['ip' => '203.0.113.200']));
        $this->assertFalse($inCidr->matches(['ip' => '192.168.1.1']));
    }

    public function testInCidrBareAddressIsHostRoute(): void
    {
        $ipv4 = Condition::inCidr('ip', ['203.0.113.5']);
        $ipv6 = Condition::inCidr('ip', ['2001:db8::1']);

        $this->assertTrue($ipv4->matches(['ip' => '203.0.113.5']));
        $this->assertFalse($ipv4->matches(['ip' => '203.0.113.6']));

        $this->assertTrue($ipv6->matches(['ip' => '2001:db8::1']));
        $this->assertFalse($ipv6->matches(['ip' => '2001:db8::2']));
    }

    public function testInCidrPrefixBoundaries(): void
    {
        $zero = Condition::inCidr('ip', ['0.0.0.0/0']);
        $zeroV6 = Condition::inCidr('ip', ['::/0']);
        $nonByteAligned = Condition::inCidr('ip', ['192.168.1.64/26']);

        $this->assertTrue($zero->matches(['ip' => '8.8.8.8']));
        $this->assertTrue($zeroV6->matches(['ip' => '2001:db8::1']));

        $this->assertTrue($nonByteAligned->matches(['ip' => '192.168.1.100']));
        $this->assertFalse($nonByteAligned->matches(['ip' => '192.168.1.200']));
    }

    public function testInCidrNeverMatchesAcrossAddressFamilies(): void
    {
        $ipv6Block = Condition::inCidr('ip', ['2001:db8::/32']);
        $ipv4Block = Condition::inCidr('ip', ['203.0.113.0/24']);

        $this->assertFalse($ipv6Block->matches(['ip' => '203.0.113.5']));
        $this->assertFalse($ipv4Block->matches(['ip' => '2001:db8::1']));

        // /0 in one family still never matches the other.
        $this->assertFalse(Condition::inCidr('ip', ['0.0.0.0/0'])->matches(['ip' => '2001:db8::1']));
        $this->assertFalse(Condition::inCidr('ip', ['::/0'])->matches(['ip' => '8.8.8.8']));
    }

    public function testMalformedCidrEntriesNeverContainAnAddress(): void
    {
        $this->assertFalse(Condition::inCidr('ip', ['garbage'])->matches(['ip' => '203.0.113.5']));
        $this->assertFalse(Condition::inCidr('ip', ['203.0.113.0/999'])->matches(['ip' => '203.0.113.5']));
        $this->assertFalse(Condition::inCidr('ip', ['203.0.113.0/-1'])->matches(['ip' => '203.0.113.5']));
        $this->assertFalse(Condition::inCidr('ip', [])->matches(['ip' => '203.0.113.5']));

        // A malformed entry is skipped without poisoning valid siblings.
        $this->assertTrue(Condition::inCidr('ip', ['garbage', '203.0.113.0/24'])->matches(['ip' => '203.0.113.5']));
        $this->assertFalse(Condition::notInCidr('ip', ['garbage', '203.0.113.0/24'])->matches(['ip' => '203.0.113.5']));
        $this->assertTrue(Condition::notInCidr('ip', ['garbage', '203.0.113.0/24'])->matches(['ip' => '198.51.100.5']));
    }

    public function testCidrOperatorsWithoutUsableEntriesMatchNothing(): void
    {
        $address = ['ip' => '203.0.113.5'];

        $this->assertFalse(Condition::inCidr('ip', [])->matches($address));
        $this->assertFalse(Condition::notInCidr('ip', [])->matches($address));

        $this->assertFalse(Condition::inCidr('ip', ['garbage', '203.0.113.0/999'])->matches($address));
        $this->assertFalse(Condition::notInCidr('ip', ['garbage', '203.0.113.0/999'])->matches($address));
    }

    public function testMalformedAttributeAddressFailsClosedForBothCidrOperators(): void
    {
        $inCidr = Condition::inCidr('ip', ['203.0.113.0/24']);
        $notInCidr = Condition::notInCidr('ip', ['203.0.113.0/24']);

        // An unparseable address is not provably inside nor provably outside,
        // so neither operator matches.
        foreach (['not-an-ip', '', null, ['203.0.113.5'], 42] as $malformed) {
            $this->assertFalse($inCidr->matches(['ip' => $malformed]));
            $this->assertFalse($notInCidr->matches(['ip' => $malformed]));
        }

        $this->assertFalse($inCidr->matches([]));
        $this->assertFalse($notInCidr->matches([]));
    }

    public function testNotInCidrInvertsMembership(): void
    {
        $notInCidr = Condition::notInCidr('ip', ['10.0.0.0/8', '2001:db8::/32']);

        $this->assertFalse($notInCidr->matches(['ip' => '10.5.5.5']));
        $this->assertFalse($notInCidr->matches(['ip' => '2001:db8::1']));
        $this->assertTrue($notInCidr->matches(['ip' => '192.168.1.1']));
        $this->assertTrue($notInCidr->matches(['ip' => '2001:db9::1']));
    }

    public function testCidrConditionSerializationRoundTrip(): void
    {
        $condition = Condition::or([
            Condition::inCidr('ip', ['203.0.113.0/24']),
            Condition::notInCidr('ip', ['0.0.0.0/0']),
        ]);

        $parsed = Condition::decode($condition->encode());

        $this->assertTrue($parsed->matches(['ip' => '203.0.113.5']));
        $this->assertTrue($parsed->matches(['ip' => '2001:db8::1']));
        $this->assertFalse($parsed->matches(['ip' => '192.168.1.1']));
    }

    public function testNullOperatorsAndAttributeResolution(): void
    {
        $isNull = Condition::isNull('payload.signature');
        $isNotNull = Condition::isNotNull('payload.signature');

        $attributes = [
            'payload' => [
                'signature' => 'abc',
            ],
        ];

        $this->assertFalse($isNull->matches($attributes));
        $this->assertTrue($isNull->matches(['payload' => []]));

        $this->assertTrue($isNotNull->matches($attributes));
        $this->assertFalse($isNotNull->matches(['payload' => []]));
    }

    public function testLogicalOperatorsNested(): void
    {
        $nested = Condition::and([
            Condition::equal('method', ['POST']),
            Condition::or([
                Condition::equal('path', ['/admin']),
                Condition::startsWith('path', '/internal'),
            ]),
            Condition::notContains('headers.user-agent', ['bot']),
        ]);

        $this->assertTrue($nested->matches([
            'method' => 'POST',
            'path' => '/internal/tools',
            'headers' => [
                'user-agent' => 'Mozilla',
            ],
        ]));

        $this->assertFalse($nested->matches([
            'method' => 'POST',
            'path' => '/public',
            'headers' => [
                'user-agent' => 'Mozilla',
            ],
        ]));

        $this->assertFalse($nested->matches([
            'method' => 'POST',
            'path' => '/internal/ops',
            'headers' => [
                'user-agent' => 'bot',
            ],
        ]));
    }

    public function testConditionSerializationRoundTrip(): void
    {
        $condition = Condition::and([
            Condition::equal('ip', ['127.0.0.1']),
            Condition::or([
                Condition::startsWith('path', '/api'),
                Condition::endsWith('path', '.json'),
            ]),
        ]);

        $json = $condition->encode();
        $parsed = Condition::decode($json);

        $this->assertTrue($parsed->matches(['ip' => '127.0.0.1', 'path' => '/api/users']));
        $this->assertTrue($parsed->matches(['ip' => '127.0.0.1', 'path' => '/status.json']));
        $this->assertFalse($parsed->matches(['ip' => '127.0.0.1', 'path' => '/web']));
    }

    public function testMatchingIsCaseInsensitive(): void
    {
        // equal: rule value and resolved attribute differ only in case.
        $country = Condition::equal('country', ['in']);
        $this->assertTrue($country->matches(['country' => 'IN']));
        $this->assertTrue($country->matches(['country' => 'In']));
        $this->assertFalse($country->matches(['country' => 'US']));

        // notEqual inherits the same folding.
        $notCountry = Condition::notEqual('country', 'in');
        $this->assertFalse($notCountry->matches(['country' => 'IN']));
        $this->assertTrue($notCountry->matches(['country' => 'US']));

        // contains: both the string-haystack and array-membership forms fold case.
        $stringContains = Condition::contains('userAgent', ['CURL']);
        $this->assertTrue($stringContains->matches(['userAgent' => 'curl/8.4']));

        $arrayContains = Condition::contains('tags', ['Security']);
        $this->assertTrue($arrayContains->matches(['tags' => ['security', 'waf']]));

        // Array membership keeps the old array_intersect() loose scalar
        // semantics: an int needle still matches a numeric-string element.
        $numericContains = Condition::contains('codes', [200]);
        $this->assertTrue($numericContains->matches(['codes' => ['200', '404']]));

        // prefix / suffix fold case too.
        $startsWith = Condition::startsWith('path', '/API');
        $this->assertTrue($startsWith->matches(['path' => '/api/v1']));

        $endsWith = Condition::endsWith('path', '.JSON');
        $this->assertTrue($endsWith->matches(['path' => '/status.json']));

        // Non-string values keep strict semantics (no accidental coercion).
        $numeric = Condition::equal('count', [10]);
        $this->assertTrue($numeric->matches(['count' => 10]));
        $this->assertFalse($numeric->matches(['count' => '10']));

        // Ordering operators stay case-sensitive so string boundaries remain
        // deterministic — only equality/substring matching folds case.
        $between = Condition::between('name', 'BANANA', 'CHERRY');
        $this->assertFalse($between->matches(['name' => 'banana']));
        $this->assertTrue($between->matches(['name' => 'CANARY']));
    }

    public function testInvalidMethodThrowsException(): void
    {
        $this->expectException(ConditionException::class);

        Condition::fromArray([
            'method' => 'unknown',
            'attribute' => 'ip',
            'values' => [],
        ]);
    }

    public function testParseRejectsInvalidJson(): void
    {
        $this->expectException(ConditionException::class);

        Condition::decode('{"method":');
    }
}
