<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Exception\Condition as ConditionException;

class ConditionTest extends TestCase
{
    public function testConditionSerialization(): void
    {
        $condition = Condition::equal('ip', ['127.0.0.1']);

        $decoded = Condition::fromArray($condition->toArray());

        $this->assertSame($condition->getMethod(), $decoded->getMethod());
        $this->assertSame($condition->getAttribute(), $decoded->getAttribute());
        $this->assertTrue($decoded->matches(['ip' => '127.0.0.1']));
    }

    public function testLogicalCondition(): void
    {
        $condition = Condition::and([
            Condition::equal('method', ['GET']),
            Condition::notEqual('path', '/admin'),
        ]);

        $this->assertTrue($condition->matches(['method' => 'GET', 'path' => '/']));
        $this->assertFalse($condition->matches(['method' => 'POST', 'path' => '/']));
    }

    public function testParsingFromJson(): void
    {
        $condition = Condition::startsWith('path', '/api');
        $json = $condition->toString();

        $parsed = Condition::parse($json);

        $this->assertTrue($parsed->matches(['path' => '/api/v1/users']));
        $this->assertFalse($parsed->matches(['path' => '/web']));
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
}
