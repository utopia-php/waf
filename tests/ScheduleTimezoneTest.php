<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Utopia\WAF\Exception\Schedule as ScheduleException;
use Utopia\WAF\Schedule;

class ScheduleTimezoneTest extends TestCase
{
    /**
     * Every instant is given in UTC; the comment says what the rule's local clock shows.
     *
     * @return iterable<string, array{array<string, mixed>, string, bool}>
     */
    public static function activity(): iterable
    {
        $kolkataWeekends = ['mode' => 'weekends', 'timezone' => 'Asia/Kolkata'];
        yield 'IST weekends: Fri 23:59 IST' => [$kolkataWeekends, '2026-11-06 18:29', false];
        yield 'IST weekends: Sat 00:00 IST' => [$kolkataWeekends, '2026-11-06 18:30', true];
        yield 'IST weekends: Sun 23:59 IST' => [$kolkataWeekends, '2026-11-08 18:29', true];
        yield 'IST weekends: Mon 00:00 IST' => [$kolkataWeekends, '2026-11-08 18:30', false];

        $berlinOffice = ['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00', 'timezone' => 'Europe/Berlin'];
        yield 'Berlin winter: 08:59 CET' => [$berlinOffice, '2026-03-27 07:59', false];
        yield 'Berlin winter: 09:00 CET' => [$berlinOffice, '2026-03-27 08:00', true];
        yield 'Berlin winter: 17:00 CET' => [$berlinOffice, '2026-03-27 16:00', false];
        yield 'Berlin summer: 08:59 CEST' => [$berlinOffice, '2026-03-30 06:59', false];
        yield 'Berlin summer: 09:00 CEST' => [$berlinOffice, '2026-03-30 07:00', true];
        yield 'Berlin summer: 16:59 CEST' => [$berlinOffice, '2026-03-30 14:59', true];
        yield 'Berlin summer: 17:00 CEST' => [$berlinOffice, '2026-03-30 15:00', false];

        // 2026-03-29: Berlin clocks jump from 02:00 CET to 03:00 CEST.
        $startsInTheGap = ['mode' => 'daily', 'startTime' => '02:30', 'endTime' => '04:00', 'timezone' => 'Europe/Berlin'];
        yield 'spring forward: 01:59 CET, before the jump' => [$startsInTheGap, '2026-03-29 00:59', false];
        yield 'spring forward: 03:00 CEST, opens after the jump' => [$startsInTheGap, '2026-03-29 01:00', true];
        yield 'spring forward: 03:59 CEST' => [$startsInTheGap, '2026-03-29 01:59', true];
        yield 'spring forward: 04:00 CEST, closes' => [$startsInTheGap, '2026-03-29 02:00', false];

        // 2026-10-25: Berlin clocks fall back from 03:00 CEST to 02:00 CET, so 02:00-02:59 happens twice.
        $repeatedHour = ['mode' => 'daily', 'startTime' => '02:00', 'endTime' => '02:30', 'timezone' => 'Europe/Berlin'];
        yield 'fall back: 02:00 CEST, first time' => [$repeatedHour, '2026-10-25 00:00', true];
        yield 'fall back: 02:29 CEST, first time' => [$repeatedHour, '2026-10-25 00:29', true];
        yield 'fall back: 02:30 CEST, first time' => [$repeatedHour, '2026-10-25 00:30', false];
        yield 'fall back: 02:00 CET, second time' => [$repeatedHour, '2026-10-25 01:00', true];
        yield 'fall back: 02:29 CET, second time' => [$repeatedHour, '2026-10-25 01:29', true];
        yield 'fall back: 02:30 CET, second time' => [$repeatedHour, '2026-10-25 01:30', false];

        $mondays = ['mode' => 'weekly', 'days' => [1]];
        yield 'same instant: Tue 02:00 in Kiritimati (+14)' => [$mondays + ['timezone' => 'Pacific/Kiritimati'], '2026-11-02 12:00', false];
        yield 'same instant: Mon 01:00 in Pago Pago (-11)' => [$mondays + ['timezone' => 'Pacific/Pago_Pago'], '2026-11-02 12:00', true];
        yield 'same instant: Mon 12:00 in UTC' => [$mondays, '2026-11-02 12:00', true];

        $newYorkFridayNights = ['mode' => 'weekly', 'days' => [5], 'startTime' => '22:00', 'endTime' => '02:00', 'timezone' => 'America/New_York'];
        yield 'New York: Fri 22:00 EST is Sat in UTC' => [$newYorkFridayNights, '2026-11-07 03:00', true];
        yield 'New York: Sat 01:59 EST' => [$newYorkFridayNights, '2026-11-07 06:59', true];
        yield 'New York: Sat 02:00 EST' => [$newYorkFridayNights, '2026-11-07 07:00', false];

        $kolkataEveryThirdDay = ['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-11-02', 'timezone' => 'Asia/Kolkata'];
        yield 'anchor in the zone: Sun 23:59 IST, the day before' => [$kolkataEveryThirdDay, '2026-11-01 18:29', false];
        yield 'anchor in the zone: Mon 00:00 IST, the anchor' => [$kolkataEveryThirdDay, '2026-11-01 18:30', true];
        yield 'anchor in the zone: three days later' => [$kolkataEveryThirdDay, '2026-11-04 18:30', true];

        $kolkataEveryOtherMonday = ['mode' => 'biweekly', 'days' => [1], 'anchor' => '2026-11-02', 'timezone' => 'Asia/Kolkata'];
        yield 'biweekly in the zone: anchor monday starts at 00:00 IST' => [$kolkataEveryOtherMonday, '2026-11-01 18:30', true];
        yield 'biweekly in the zone: off week' => [$kolkataEveryOtherMonday, '2026-11-08 18:30', false];
        yield 'biweekly in the zone: on week' => [$kolkataEveryOtherMonday, '2026-11-15 18:30', true];
    }

    /**
     * @param array<string, mixed> $payload
     */
    #[DataProvider('activity')]
    public function testIsActiveOnTheZonesClock(array $payload, string $utc, bool $expected): void
    {
        $this->assertSame($expected, Schedule::fromArray($payload)->isActiveAt(self::at($utc)));
    }

    public function testWindowEntirelyInsideTheSkippedHourDoesNotHappenThatDay(): void
    {
        $schedule = Schedule::fromArray(['mode' => 'daily', 'startTime' => '02:00', 'endTime' => '02:30', 'timezone' => 'Europe/Berlin']);

        $active = [];
        for ($t = self::at('2026-03-28 22:00'); $t < self::at('2026-03-29 22:00'); $t += 60) {
            if ($schedule->isActiveAt($t)) {
                $active[] = $t;
            }
        }

        $this->assertSame([], $active);
        $this->assertTrue($schedule->isActiveAt(self::at('2026-03-30 00:00')), 'next day 02:00 CEST');
    }

    public function testRepeatedHourMakesTheWindowLastTwiceAsLong(): void
    {
        $schedule = Schedule::fromArray(['mode' => 'daily', 'startTime' => '02:00', 'endTime' => '03:00', 'timezone' => 'Europe/Berlin']);

        $activeMinutes = 0;
        for ($t = self::at('2026-10-24 22:00'); $t < self::at('2026-10-25 22:00'); $t += 60) {
            $activeMinutes += $schedule->isActiveAt($t) ? 1 : 0;
        }

        $this->assertSame(120, $activeMinutes);
    }

    public function testServerTimezoneDoesNotMoveAZonedSchedule(): void
    {
        $original = \date_default_timezone_get();
        \date_default_timezone_set('Pacific/Kiritimati');

        try {
            $schedule = Schedule::fromArray(['mode' => 'weekends', 'timezone' => 'Asia/Kolkata']);
            $fridayNightIst = $schedule->isActiveAt(self::at('2026-11-06 18:29'));
            $saturdayIst = $schedule->isActiveAt(self::at('2026-11-06 18:30'));
        } finally {
            \date_default_timezone_set($original);
        }

        $this->assertFalse($fridayNightIst);
        $this->assertTrue($saturdayIst);
    }

    public function testToArrayKeepsTheZoneAndDropsUtc(): void
    {
        $this->assertSame(
            ['mode' => 'weekends', 'timezone' => 'Asia/Kolkata'],
            Schedule::fromArray(['mode' => 'weekends', 'timezone' => 'Asia/Kolkata'])->toArray()
        );
        $this->assertSame(['mode' => 'weekends'], Schedule::fromArray(['mode' => 'weekends', 'timezone' => 'UTC'])->toArray());
        $this->assertSame(['mode' => 'weekends'], Schedule::fromArray(['mode' => 'weekends', 'timezone' => null])->toArray());
    }

    public function testUtcGivesTheSameAnswersAsNoTimezone(): void
    {
        $plain = Schedule::fromArray(['mode' => 'weekly', 'days' => [5], 'startTime' => '22:00', 'endTime' => '06:00']);
        $utc = Schedule::fromArray(['mode' => 'weekly', 'days' => [5], 'startTime' => '22:00', 'endTime' => '06:00', 'timezone' => 'UTC']);

        for ($t = self::at('2026-11-02 00:00'); $t < self::at('2026-11-09 00:00'); $t += 900) {
            $this->assertSame($plain->isActiveAt($t), $utc->isActiveAt($t), \gmdate('D H:i', $t));
        }
    }

    public function testBackwardCompatibleZoneNamesAreAccepted(): void
    {
        $calcutta = Schedule::fromArray(['mode' => 'weekends', 'timezone' => 'Asia/Calcutta']);

        $this->assertTrue($calcutta->isActiveAt(self::at('2026-11-06 18:30')));
        $this->assertFalse($calcutta->isActiveAt(self::at('2026-11-06 18:29')));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function invalidZones(): iterable
    {
        yield 'unknown name' => ['Mars/Olympus_Mons'];
        yield 'fixed offset' => ['+05:30'];
        yield 'wrong case' => ['asia/kolkata'];
        yield 'trailing space' => ['Asia/Kolkata '];
        yield 'empty' => [''];
        yield 'number' => [330];
        yield 'list' => [['Asia/Kolkata']];
    }

    #[DataProvider('invalidZones')]
    public function testRejectsInvalidZone(mixed $timezone): void
    {
        $this->expectException(ScheduleException::class);

        Schedule::fromArray(['mode' => 'daily', 'timezone' => $timezone]);
    }

    private static function at(string $utc): int
    {
        return (new \DateTimeImmutable($utc, new \DateTimeZone('UTC')))->getTimestamp();
    }
}
