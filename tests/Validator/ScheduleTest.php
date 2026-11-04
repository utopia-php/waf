<?php

namespace Utopia\WAF\Tests\Validator;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Validator\Schedule;

class ScheduleTest extends TestCase
{
    public function testAcceptsEveryMode(): void
    {
        $validator = new Schedule();

        $this->assertTrue($validator->isValid(['mode' => 'daily']));
        $this->assertTrue($validator->isValid(['mode' => 'weekly', 'days' => [1, 5], 'startTime' => '09:00', 'endTime' => '17:00']));
        $this->assertTrue($validator->isValid(['mode' => 'biweekly', 'days' => [3], 'anchor' => '2026-11-04']));
        $this->assertTrue($validator->isValid(['mode' => 'weekends', 'startTime' => '22:00', 'endTime' => '06:00']));
        $this->assertTrue($validator->isValid(['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-11-02']));
        $this->assertTrue($validator->isValid(['mode' => 'weekends', 'timezone' => 'Asia/Kolkata']));
    }

    public function testRejectionDescribesTheProblem(): void
    {
        $validator = new Schedule();

        $this->assertFalse($validator->isValid(['mode' => 'everyNDays', 'interval' => 3]));
        $this->assertStringContainsString('anchor', $validator->getDescription());

        $this->assertFalse($validator->isValid(['mode' => 'daily', 'timezone' => 'Mars/Olympus_Mons']));
        $this->assertStringContainsString('IANA', $validator->getDescription());

        $this->assertFalse($validator->isValid(['mode' => 'daily', 'startTime' => '9am', 'endTime' => '17:00', 'timezone' => 'Asia/Kolkata']));
        $this->assertStringContainsString('HH:MM', $validator->getDescription());
        $this->assertStringNotContainsString('UTC time', $validator->getDescription(), 'a zoned time is not UTC');

        $this->assertFalse($validator->isValid(['mode' => 'everyNDays', 'interval' => 3, 'anchor' => "2026-11-02\0"]));
        $this->assertStringContainsString('YYYY-MM-DD', $validator->getDescription());

        $this->assertFalse($validator->isValid('daily'));
        $this->assertStringContainsString('object', $validator->getDescription());
    }

    public function testIsAnObjectParameter(): void
    {
        $validator = new Schedule();

        $this->assertFalse($validator->isArray());
        $this->assertSame(Schedule::TYPE_OBJECT, $validator->getType());
    }
}
