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

        $json = $condition->toString();
        $parsed = Condition::parse($json);

        $this->assertTrue($parsed->matches(['ip' => '127.0.0.1', 'path' => '/api/users']));
        $this->assertTrue($parsed->matches(['ip' => '127.0.0.1', 'path' => '/status.json']));
        $this->assertFalse($parsed->matches(['ip' => '127.0.0.1', 'path' => '/web']));
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

        Condition::parse('{"method":');
    }
}
