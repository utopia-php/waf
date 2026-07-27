<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Exception\Condition as ConditionException;
use Utopia\WAF\Types\AttributeType;
use Utopia\WAF\Types\IpType;

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

    public function testEqualWithAttributeTypeMatchesCidrBlocks(): void
    {
        $types = ['ip' => new IpType()];

        $equal = Condition::equal('ip', ['203.0.113.10', '10.0.0.0/8']);
        $this->assertTrue($equal->matches(['ip' => '203.0.113.10'], $types)); // plain IP, default equality
        $this->assertTrue($equal->matches(['ip' => '10.4.20.9'], $types));    // CIDR containment
        $this->assertFalse($equal->matches(['ip' => '11.0.0.1'], $types));

        // notEqual inherits the typed semantics through negation.
        $notEqual = Condition::notEqual('ip', '10.0.0.0/8');
        $this->assertFalse($notEqual->matches(['ip' => '10.4.20.9'], $types));
        $this->assertTrue($notEqual->matches(['ip' => '11.0.0.1'], $types));

        // Nested logical conditions carry the types down.
        $nested = Condition::or([
            Condition::equal('ip', ['10.0.0.0/8']),
            Condition::equal('country', ['US']),
        ]);
        $this->assertTrue($nested->matches(['ip' => '10.1.1.1', 'country' => 'IN'], $types));
        $this->assertFalse($nested->matches(['ip' => '11.1.1.1', 'country' => 'IN'], $types));
    }

    public function testAttributeTypeIsProbedForAllOperators(): void
    {
        // Stub type: 'MATCH' => handled match, 'BLOCK' => handled no-match,
        // anything else => null (default semantics). Records every probe.
        $type = new class () implements AttributeType {
            /** @var array<array{string, mixed, mixed}> */
            public array $calls = [];

            public function compare(string $method, mixed $value, mixed $expected): ?bool
            {
                $this->calls[] = [$method, $value, $expected];

                $needles = \is_array($expected) ? $expected : [$expected];

                if (\in_array('MATCH', $needles, true)) {
                    return true;
                }

                if (\in_array('BLOCK', $needles, true)) {
                    return false;
                }

                return null;
            }

            public function validateValue(string $method, mixed $expected): ?string
            {
                return null;
            }
        };
        $types = ['tag' => $type];

        // contains: typed match wins even where default semantics would miss.
        $this->assertTrue(Condition::contains('tag', ['MATCH'])->matches(['tag' => 'nothing-alike'], $types));

        // contains: a handled "no" suppresses the default substring match.
        $this->assertFalse(Condition::contains('tag', ['BLOCK'])->matches(['tag' => 'has BLOCK inside'], $types));
        $this->assertTrue(Condition::notContains('tag', ['BLOCK'])->matches(['tag' => 'has BLOCK inside'], $types));

        // contains: unhandled needles keep default semantics.
        $this->assertTrue(Condition::contains('tag', ['inside'])->matches(['tag' => 'has BLOCK inside'], $types));

        // startsWith / endsWith and their negations probe the positive operator.
        $this->assertTrue(Condition::startsWith('tag', 'MATCH')->matches(['tag' => 'zzz'], $types));
        $this->assertFalse(Condition::notStartsWith('tag', 'MATCH')->matches(['tag' => 'zzz'], $types));
        $this->assertTrue(Condition::endsWith('tag', 'MATCH')->matches(['tag' => 'zzz'], $types));

        // Relational operators consult the type with their own method.
        $this->assertTrue(Condition::lessThan('tag', 'MATCH')->matches(['tag' => 'zzz'], $types));
        $this->assertTrue(Condition::greaterThanEqual('tag', 'MATCH')->matches(['tag' => 'zzz'], $types));

        // between probes once with the full [start, end] pair.
        $type->calls = [];
        $this->assertTrue(Condition::between('tag', 'MATCH', 'end')->matches(['tag' => 'zzz'], $types));
        $this->assertSame([[Condition::TYPE_BETWEEN, 'zzz', ['MATCH', 'end']]], $type->calls);
        $this->assertFalse(Condition::notBetween('tag', 'MATCH', 'end')->matches(['tag' => 'zzz'], $types));

        // isNull/isNotNull stay type-agnostic: never probed.
        $type->calls = [];
        $this->assertTrue(Condition::isNull('tag')->matches(['tag' => null], $types));
        $this->assertTrue(Condition::isNotNull('tag')->matches(['tag' => 'zzz'], $types));
        $this->assertSame([], $type->calls);
    }

    public function testEqualWithoutTypesKeepsPlainStringSemantics(): void
    {
        // Without a registered type a CIDR value never matches, and
        // slash-containing values on other attributes stay untouched.
        $equal = Condition::equal('ip', ['10.0.0.0/8']);
        $this->assertFalse($equal->matches(['ip' => '10.4.20.9']));

        $path = Condition::equal('path', ['/v1/health']);
        $this->assertTrue($path->matches(['path' => '/v1/health'], ['ip' => new IpType()]));
    }
}
