<?php

namespace Utopia\WAF\Tests\Validator;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Validator\Conditions;

class ConditionsTest extends TestCase
{
    public function testRejectsEmptyConditionList(): void
    {
        $validator = new Conditions();

        $this->assertFalse($validator->isValid([]));
    }

    public function testAcceptsConditionArraysAndStrings(): void
    {
        $validator = new Conditions();

        $this->assertTrue($validator->isValid([
            Condition::equal('ip', ['198.51.100.5'])->toArray(),
            Condition::startsWith('path', '/v1')->encode(),
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
            Condition::startsWith('path', '/v1')->encode(),
        ]));
    }

    public function testRejectsLongConditionStrings(): void
    {
        $validator = new Conditions(maxPayloadLength: 5);

        $this->assertFalse($validator->isValid([
            Condition::startsWith('path', '/v1')->encode(),
        ]));
    }
}
