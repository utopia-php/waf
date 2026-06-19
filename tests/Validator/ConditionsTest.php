<?php

namespace Utopia\WAF\Tests\Validator;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Validator\Conditions;

class ConditionsTest extends TestCase
{
    public function testReturnsArrayType(): void
    {
        $validator = new Conditions();

        $this->assertTrue($validator->isArray());
        $this->assertSame(Conditions::TYPE_ARRAY, $validator->getType());
    }

    public function testRejectsEmptyConditionList(): void
    {
        $validator = new Conditions();

        $this->assertFalse($validator->isValid([]));
    }

    public function testAcceptsConditionArrays(): void
    {
        $validator = new Conditions();

        $this->assertTrue($validator->isValid([
            Condition::equal('ip', ['198.51.100.5'])->toArray(),
            Condition::startsWith('path', '/v1')->toArray(),
        ]));
    }

    public function testAcceptsEncodedConditionStrings(): void
    {
        $validator = new Conditions();

        $this->assertTrue($validator->isValid([
            Condition::startsWith('path', '/v1')->encode(),
        ]));
    }

    public function testRejectsInvalidConditionStrings(): void
    {
        $validator = new Conditions();

        $this->assertFalse($validator->isValid([
            '{"method":',
        ]));
    }

    public function testRejectsInvalidConditionArray(): void
    {
        $validator = new Conditions();

        $this->assertFalse($validator->isValid([
            [
                'method' => 'unknown',
                'attribute' => 'ip',
                'values' => ['1.2.3.4'],
            ],
        ]));
    }

    public function testRejectsTooManyConditions(): void
    {
        $validator = new Conditions(maxConditions: 1);

        $this->assertFalse($validator->isValid([
            Condition::equal('ip', ['198.51.100.5'])->toArray(),
            Condition::startsWith('path', '/v1')->toArray(),
        ]));
    }

    public function testRejectsTooManyNestedConditions(): void
    {
        $validator = new Conditions(maxConditions: 2);

        $this->assertFalse($validator->isValid([
            Condition::and([
                Condition::equal('ip', ['198.51.100.5']),
                Condition::startsWith('path', '/v1'),
            ])->toArray(),
        ]));
    }

    public function testRejectsTooManyNestedEncodedConditions(): void
    {
        $validator = new Conditions(maxConditions: 2);

        $this->assertFalse($validator->isValid([
            Condition::and([
                Condition::equal('ip', ['198.51.100.5']),
                Condition::startsWith('path', '/v1'),
            ])->encode(),
        ]));
    }

    public function testRejectsLongConditionArrays(): void
    {
        $validator = new Conditions(maxPayloadLength: 64);

        $this->assertFalse($validator->isValid([
            Condition::equal('ip', [\str_repeat('1', 128)])->toArray(),
        ]));
    }

    public function testRejectsLongConditionStrings(): void
    {
        $validator = new Conditions(maxPayloadLength: 64);

        $this->assertFalse($validator->isValid([
            Condition::equal('ip', [\str_repeat('1', 128)])->encode(),
        ]));
    }

    public function testRejectsEmptyLogicalConditions(): void
    {
        $validator = new Conditions();

        $this->assertFalse($validator->isValid([
            [
                'method' => Condition::TYPE_AND,
                'values' => [],
            ],
        ]));
    }
}
