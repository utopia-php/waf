<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Utopia\WAF\Exception\Schedule as ScheduleException;
use Utopia\WAF\Schedule;

class ScheduleTest extends TestCase
{
    /**
     * 2026-11-02 is a Monday.
     *
     * @return iterable<string, array{array<string, mixed>, string, bool}>
     */
    public static function activity(): iterable
    {
        $office = ['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00'];
        yield 'daily window: minute before start' => [$office, '2026-11-04 08:59', false];
        yield 'daily window: start minute is inside' => [$office, '2026-11-04 09:00', true];
        yield 'daily window: last minute is inside' => [$office, '2026-11-04 16:59', true];
        yield 'daily window: end minute is outside' => [$office, '2026-11-04 17:00', false];

        $allDay = ['mode' => 'daily'];
        yield 'daily without times: midnight' => [$allDay, '2026-11-04 00:00', true];
        yield 'daily without times: last minute' => [$allDay, '2026-11-04 23:59', true];

        $untilMidnight = ['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '00:00'];
        yield 'end 00:00 runs to midnight' => [$untilMidnight, '2026-11-04 23:59', true];
        yield 'end 00:00 stops at midnight' => [$untilMidnight, '2026-11-05 00:00', false];
        yield 'end 00:00 starts at start' => [$untilMidnight, '2026-11-05 08:59', false];

        $fridayNights = ['mode' => 'weekly', 'days' => [5], 'startTime' => '22:00', 'endTime' => '06:00'];
        yield 'overnight: friday before start' => [$fridayNights, '2026-11-06 21:59', false];
        yield 'overnight: friday at start' => [$fridayNights, '2026-11-06 22:00', true];
        yield 'overnight: saturday morning belongs to friday' => [$fridayNights, '2026-11-07 05:59', true];
        yield 'overnight: saturday at end' => [$fridayNights, '2026-11-07 06:00', false];
        yield 'overnight: saturday night is not selected' => [$fridayNights, '2026-11-07 22:00', false];
        yield 'overnight: friday morning belongs to thursday' => [$fridayNights, '2026-11-06 01:00', false];

        $weekdays = ['mode' => 'weekly', 'days' => [1, 3]];
        yield 'weekly: monday selected' => [$weekdays, '2026-11-02 12:00', true];
        yield 'weekly: tuesday not selected' => [$weekdays, '2026-11-03 12:00', false];
        yield 'weekly: wednesday selected' => [$weekdays, '2026-11-04 12:00', true];
        yield 'weekly: sunday not selected' => [$weekdays, '2026-11-08 12:00', false];

        $weekends = ['mode' => 'weekends'];
        yield 'weekends: friday last minute' => [$weekends, '2026-11-06 23:59', false];
        yield 'weekends: saturday first minute' => [$weekends, '2026-11-07 00:00', true];
        yield 'weekends: sunday last minute' => [$weekends, '2026-11-08 23:59', true];
        yield 'weekends: monday first minute' => [$weekends, '2026-11-09 00:00', false];

        $everyOtherMonday = ['mode' => 'biweekly', 'days' => [1], 'anchor' => '2026-11-02'];
        yield 'biweekly: anchor monday' => [$everyOtherMonday, '2026-11-02 12:00', true];
        yield 'biweekly: off week' => [$everyOtherMonday, '2026-11-09 12:00', false];
        yield 'biweekly: on week' => [$everyOtherMonday, '2026-11-16 12:00', true];
        yield 'biweekly: before anchor' => [$everyOtherMonday, '2026-10-19 12:00', false];
        yield 'biweekly: on week across the year' => [$everyOtherMonday, '2026-12-28 12:00', true];
        yield 'biweekly: off week across the year' => [$everyOtherMonday, '2027-01-04 12:00', false];

        $midweekAnchor = ['mode' => 'biweekly', 'days' => [1, 3], 'anchor' => '2026-11-04'];
        yield 'biweekly: anchor week monday is before anchor' => [$midweekAnchor, '2026-11-02 12:00', false];
        yield 'biweekly: anchor wednesday' => [$midweekAnchor, '2026-11-04 12:00', true];
        yield 'biweekly: off week monday' => [$midweekAnchor, '2026-11-09 12:00', false];
        yield 'biweekly: on week monday' => [$midweekAnchor, '2026-11-16 12:00', true];
        yield 'biweekly: on week wednesday' => [$midweekAnchor, '2026-11-18 12:00', true];

        $everyThirdDay = ['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-11-02'];
        yield 'every 3 days: anchor' => [$everyThirdDay, '2026-11-02 00:00', true];
        yield 'every 3 days: day after anchor' => [$everyThirdDay, '2026-11-03 12:00', false];
        yield 'every 3 days: third day after anchor' => [$everyThirdDay, '2026-11-05 12:00', true];
        yield 'every 3 days: day before anchor' => [$everyThirdDay, '2026-11-01 12:00', false];
        yield 'every 3 days: on cycle but before anchor' => [$everyThirdDay, '2026-10-30 12:00', false];

        $everyThirdNight = ['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-11-02', 'startTime' => '22:00', 'endTime' => '02:00'];
        yield 'every 3 nights: anchor night' => [$everyThirdNight, '2026-11-02 23:00', true];
        yield 'every 3 nights: morning after anchor' => [$everyThirdNight, '2026-11-03 01:00', true];
        yield 'every 3 nights: next night is off' => [$everyThirdNight, '2026-11-03 23:00', false];
        yield 'every 3 nights: anchor morning belongs to the day before' => [$everyThirdNight, '2026-11-02 01:00', false];

        $lastMinute = ['mode' => 'daily', 'startTime' => '23:59', 'endTime' => '00:00'];
        yield 'one-minute window before midnight: 23:58' => [$lastMinute, '2026-11-04 23:58', false];
        yield 'one-minute window before midnight: 23:59' => [$lastMinute, '2026-11-04 23:59', true];
        yield 'one-minute window before midnight: 00:00' => [$lastMinute, '2026-11-05 00:00', false];

        $firstMinute = ['mode' => 'daily', 'startTime' => '00:00', 'endTime' => '00:01'];
        yield 'one-minute window after midnight: 00:00' => [$firstMinute, '2026-11-04 00:00', true];
        yield 'one-minute window after midnight: 00:01' => [$firstMinute, '2026-11-04 00:01', false];
        yield 'one-minute window after midnight: 23:59' => [$firstMinute, '2026-11-04 23:59', false];

        $allButMidnight = ['mode' => 'daily', 'startTime' => '00:01', 'endTime' => '00:00'];
        yield 'all day but the midnight minute: 00:00' => [$allButMidnight, '2026-11-04 00:00', false];
        yield 'all day but the midnight minute: 00:01' => [$allButMidnight, '2026-11-04 00:01', true];
        yield 'all day but the midnight minute: 23:59' => [$allButMidnight, '2026-11-04 23:59', true];

        $sundayNights = ['mode' => 'weekly', 'days' => [7], 'startTime' => '22:00', 'endTime' => '02:00'];
        yield 'overnight across the week: monday morning belongs to sunday' => [$sundayNights, '2026-11-09 01:59', true];
        yield 'overnight across the week: monday at end' => [$sundayNights, '2026-11-09 02:00', false];
        yield 'overnight across the week: sunday morning belongs to saturday' => [$sundayNights, '2026-11-08 01:00', false];

        $weekendLateNights = ['mode' => 'weekends', 'startTime' => '23:00', 'endTime' => '01:00'];
        yield 'weekend overnight: saturday morning belongs to friday' => [$weekendLateNights, '2026-11-07 00:30', false];
        yield 'weekend overnight: sunday morning belongs to saturday' => [$weekendLateNights, '2026-11-08 00:30', true];
        yield 'weekend overnight: monday morning belongs to sunday' => [$weekendLateNights, '2026-11-09 00:30', true];
        yield 'weekend overnight: friday night is not a weekend' => [$weekendLateNights, '2026-11-06 23:30', false];

        $nights = ['mode' => 'daily', 'startTime' => '22:00', 'endTime' => '02:00'];
        yield 'overnight across the year: new year 01:59' => [$nights, '2027-01-01 01:59', true];
        yield 'overnight across the year: new year 02:00' => [$nights, '2027-01-01 02:00', false];
        yield 'overnight across a month: march 1st after a leap day' => [$nights, '2028-03-01 01:00', true];

        $office = ['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00'];
        yield 'no DST: EU spring-forward day still opens at 09:00 UTC' => [$office, '2026-03-29 09:00', true];
        yield 'no DST: EU spring-forward day still closed at 08:59 UTC' => [$office, '2026-03-29 08:59', false];
        yield 'no DST: US fall-back day still closes at 17:00 UTC' => [$office, '2026-11-01 17:00', false];

        yield 'leap years: 2100 is not one, so march 1st is a monday' => [['mode' => 'weekly', 'days' => [1]], '2100-03-01 12:00', true];
        yield 'leap years: 2100 march 1st is not a tuesday' => [['mode' => 'weekly', 'days' => [2]], '2100-03-01 12:00', false];

        $acrossLeapDay = ['mode' => 'everyNDays', 'interval' => 2, 'anchor' => '2028-02-28'];
        yield 'every 2 days across a leap day: feb 29 is off' => [$acrossLeapDay, '2028-02-29 12:00', false];
        yield 'every 2 days across a leap day: mar 1 is on' => [$acrossLeapDay, '2028-03-01 12:00', true];

        $yearlyFromLeapDay = ['mode' => 'everyNDays', 'interval' => 365, 'anchor' => '2028-02-29'];
        yield 'every 365 days from a leap day: anchor' => [$yearlyFromLeapDay, '2028-02-29 12:00', true];
        yield 'every 365 days from a leap day: lands on feb 28' => [$yearlyFromLeapDay, '2029-02-28 12:00', true];
        yield 'every 365 days from a leap day: not mar 1' => [$yearlyFromLeapDay, '2029-03-01 12:00', false];

        $everyOtherMondayFromSunday = ['mode' => 'biweekly', 'days' => [1], 'anchor' => '2026-11-08'];
        yield 'biweekly anchored on a sunday: next monday starts an off week' => [$everyOtherMondayFromSunday, '2026-11-09 12:00', false];
        yield 'biweekly anchored on a sunday: the monday after is on' => [$everyOtherMondayFromSunday, '2026-11-16 12:00', true];

        $everyOtherSunday = ['mode' => 'biweekly', 'days' => [7], 'anchor' => '2026-11-08'];
        yield 'biweekly sundays: anchor' => [$everyOtherSunday, '2026-11-08 12:00', true];
        yield 'biweekly sundays: off week' => [$everyOtherSunday, '2026-11-15 12:00', false];
        yield 'biweekly sundays: on week' => [$everyOtherSunday, '2026-11-22 12:00', true];

        yield 'biweekly a year later: week 52 is on' => [$everyOtherMonday, '2027-11-01 12:00', true];
        yield 'biweekly a year later: week 53 is off' => [$everyOtherMonday, '2027-11-08 12:00', false];

        yield 'before 1970: 1969-12-31 was a wednesday' => [['mode' => 'weekly', 'days' => [3]], '1969-12-31 12:00', true];
        yield 'before 1970: 1969-12-31 was not a thursday' => [['mode' => 'weekly', 'days' => [4]], '1969-12-31 12:00', false];
        yield 'before 1970: late evening window' => [['mode' => 'daily', 'startTime' => '23:00', 'endTime' => '00:00'], '1969-12-31 23:30', true];
        yield 'across 1970: thursday morning belongs to wednesday' => [['mode' => 'weekly', 'days' => [3], 'startTime' => '22:00', 'endTime' => '02:00'], '1970-01-01 01:00', true];

        $fromBefore1970 = ['mode' => 'everyNDays', 'interval' => 2, 'anchor' => '1969-12-30'];
        yield 'anchor before 1970: two days later is on' => [$fromBefore1970, '1970-01-01 12:00', true];
        yield 'anchor before 1970: the day after is off' => [$fromBefore1970, '1969-12-31 12:00', false];

        yield 'past 2038: window still opens' => [['mode' => 'daily', 'startTime' => '03:00', 'endTime' => '04:00'], '2038-01-19 03:14', true];
        yield 'past 2038: window still closes' => [['mode' => 'daily', 'startTime' => '03:00', 'endTime' => '04:00'], '2038-01-19 04:00', false];
    }

    /**
     * @param array<string, mixed> $payload
     */
    #[DataProvider('activity')]
    public function testIsActiveAt(array $payload, string $utc, bool $expected): void
    {
        $this->assertSame($expected, Schedule::fromArray($payload)->isActiveAt(self::at($utc)));
    }

    public function testSecondsInsideTheEndMinuteAreOutside(): void
    {
        $schedule = Schedule::fromArray(['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00']);

        $this->assertTrue($schedule->isActiveAt(self::at('2026-11-04 16:59') + 59));
        $this->assertFalse($schedule->isActiveAt(self::at('2026-11-04 17:00')));
        $this->assertFalse($schedule->isActiveAt(self::at('2026-11-04 17:00') + 1));
    }

    public function testSecondsBeforeTheStartMinuteAreOutside(): void
    {
        $schedule = Schedule::fromArray(['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00']);

        $this->assertFalse($schedule->isActiveAt(self::at('2026-11-04 08:59') + 59));
        $this->assertTrue($schedule->isActiveAt(self::at('2026-11-04 09:00')));
    }

    public function testOvernightTailEndsAtTheEndMinuteToTheSecond(): void
    {
        $schedule = Schedule::fromArray(['mode' => 'weekly', 'days' => [5], 'startTime' => '22:00', 'endTime' => '06:00']);

        $this->assertTrue($schedule->isActiveAt(self::at('2026-11-07 05:59') + 59));
        $this->assertFalse($schedule->isActiveAt(self::at('2026-11-07 06:00')));
    }

    /**
     * Zones far from UTC in both directions, plus half- and quarter-hour offsets.
     *
     * @return iterable<string, array{string}>
     */
    public static function serverTimezones(): iterable
    {
        foreach (['UTC', 'Asia/Kolkata', 'Asia/Kathmandu', 'America/St_Johns', 'Pacific/Kiritimati', 'Pacific/Pago_Pago', 'America/Los_Angeles'] as $zone) {
            yield $zone => [$zone];
        }
    }

    #[DataProvider('serverTimezones')]
    public function testServerTimezoneDoesNotMoveTheSchedule(string $zone): void
    {
        $original = \date_default_timezone_get();
        \date_default_timezone_set($zone);

        try {
            // Built under the server zone, so anchor parsing is covered too.
            $everyThirdDay = Schedule::fromArray(['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-11-02']);
            $fridayNights = Schedule::fromArray(['mode' => 'weekly', 'days' => [5], 'startTime' => '22:00', 'endTime' => '06:00']);
            $everyOtherMonday = Schedule::fromArray(['mode' => 'biweekly', 'days' => [1], 'anchor' => '2026-11-02']);
        } finally {
            \date_default_timezone_set($original);
        }

        $this->assertTrue($everyThirdDay->isActiveAt(self::at('2026-11-02 00:00')));
        $this->assertFalse($everyThirdDay->isActiveAt(self::at('2026-11-01 23:59')));
        $this->assertFalse($everyThirdDay->isActiveAt(self::at('2026-11-03 00:00')));
        $this->assertTrue($everyThirdDay->isActiveAt(self::at('2026-11-05 00:00')));

        $this->assertFalse($fridayNights->isActiveAt(self::at('2026-11-06 21:59')));
        $this->assertTrue($fridayNights->isActiveAt(self::at('2026-11-06 22:00')));
        $this->assertTrue($fridayNights->isActiveAt(self::at('2026-11-07 05:59')));
        $this->assertFalse($fridayNights->isActiveAt(self::at('2026-11-07 06:00')));

        $this->assertTrue($everyOtherMonday->isActiveAt(self::at('2026-11-02 00:00')));
        $this->assertFalse($everyOtherMonday->isActiveAt(self::at('2026-11-01 23:59')));
        $this->assertFalse($everyOtherMonday->isActiveAt(self::at('2026-11-09 00:00')));
    }

    public function testAnchorIsParsedAsUtcWhateverTheServerZone(): void
    {
        $original = \date_default_timezone_get();
        \date_default_timezone_set('Pacific/Kiritimati');

        try {
            $schedule = Schedule::fromArray(['mode' => 'everyNDays', 'interval' => 2, 'anchor' => '2026-11-02']);
        } finally {
            \date_default_timezone_set($original);
        }

        $this->assertSame('2026-11-02', $schedule->toArray()['anchor'] ?? null);
        $this->assertTrue($schedule->isActiveAt(self::at('2026-11-02 00:00')));
        $this->assertFalse($schedule->isActiveAt(self::at('2026-11-01 23:59')));
    }

    public function testToArrayIsCanonical(): void
    {
        $schedule = Schedule::fromArray([
            'mode' => 'biweekly',
            'days' => [5, 1, 3],
            'anchor' => '2026-11-02',
            'interval' => null,
            'startTime' => '22:00',
            'endTime' => '06:00',
        ]);

        $this->assertSame([
            'mode' => 'biweekly',
            'days' => [1, 3, 5],
            'anchor' => '2026-11-02',
            'startTime' => '22:00',
            'endTime' => '06:00',
        ], $schedule->toArray());

        $this->assertSame($schedule->toArray(), Schedule::fromArray($schedule->toArray())->toArray());
        $this->assertSame(['mode' => 'weekends'], Schedule::fromArray(['mode' => 'weekends'])->toArray());
    }

    /**
     * @return iterable<string, array{array<mixed>}>
     */
    public static function invalid(): iterable
    {
        yield 'missing mode' => [[]];
        yield 'unknown mode' => [['mode' => 'monthly']];
        yield 'unknown key' => [['mode' => 'daily', 'tz' => 'UTC']];
        yield 'weekly without days' => [['mode' => 'weekly']];
        yield 'weekly with empty days' => [['mode' => 'weekly', 'days' => []]];
        yield 'weekly with day 0' => [['mode' => 'weekly', 'days' => [0]]];
        yield 'weekly with day 8' => [['mode' => 'weekly', 'days' => [8]]];
        yield 'weekly with string day' => [['mode' => 'weekly', 'days' => ['1']]];
        yield 'weekly with repeated day' => [['mode' => 'weekly', 'days' => [1, 1]]];
        yield 'weekly with keyed days' => [['mode' => 'weekly', 'days' => ['mon' => 1]]];
        yield 'daily with days' => [['mode' => 'daily', 'days' => [1]]];
        yield 'weekends with days' => [['mode' => 'weekends', 'days' => [6, 7]]];
        yield 'weekly with anchor' => [['mode' => 'weekly', 'days' => [1], 'anchor' => '2026-11-02']];
        yield 'biweekly without anchor' => [['mode' => 'biweekly', 'days' => [1]]];
        yield 'everyNDays without interval' => [['mode' => 'everyNDays', 'anchor' => '2026-11-02']];
        yield 'everyNDays without anchor' => [['mode' => 'everyNDays', 'interval' => 3]];
        yield 'everyNDays interval 1' => [['mode' => 'everyNDays', 'interval' => 1, 'anchor' => '2026-11-02']];
        yield 'everyNDays interval 366' => [['mode' => 'everyNDays', 'interval' => 366, 'anchor' => '2026-11-02']];
        yield 'everyNDays string interval' => [['mode' => 'everyNDays', 'interval' => '3', 'anchor' => '2026-11-02']];
        yield 'daily with interval' => [['mode' => 'daily', 'interval' => 3]];
        yield 'anchor that does not exist' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-02-30']];
        yield 'anchor with a time' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-11-02T00:00:00Z']];
        yield 'anchor without padding' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-11-2']];
        yield 'start without end' => [['mode' => 'daily', 'startTime' => '09:00']];
        yield 'end without start' => [['mode' => 'daily', 'endTime' => '17:00']];
        yield 'start equals end' => [['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '09:00']];
        yield 'hour 24' => [['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '24:00']];
        yield 'minute 60' => [['mode' => 'daily', 'startTime' => '09:60', 'endTime' => '17:00']];
        yield 'time with seconds' => [['mode' => 'daily', 'startTime' => '09:00:00', 'endTime' => '17:00:00']];
        yield 'time without padding' => [['mode' => 'daily', 'startTime' => '9:00', 'endTime' => '17:00']];
        yield 'numeric time' => [['mode' => 'daily', 'startTime' => 900, 'endTime' => 1700]];
        yield 'time with a trailing newline' => [['mode' => 'daily', 'startTime' => "09:00\n", 'endTime' => '17:00']];
        yield 'time with surrounding spaces' => [['mode' => 'daily', 'startTime' => ' 09:00', 'endTime' => '17:00 ']];
        yield 'anchor with a trailing newline' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => "2026-11-02\n"]];
        yield 'anchor that is a null byte' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => "\0"]];
        yield 'anchor with a trailing null byte' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => "2026-11-02\0"]];
        yield 'anchor with a leading null byte' => [['mode' => 'biweekly', 'days' => [1], 'anchor' => "\0002026-11-02"]];
        yield 'anchor with a null byte inside' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => "2026-11\0-02"]];
        yield 'anchor on a day that is not a leap day' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2027-02-29']];
        yield 'anchor with a five digit year' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '10000-01-01']];
    }

    /**
     * @param array<mixed> $payload
     */
    #[DataProvider('invalid')]
    public function testRejectsInvalidSchedule(array $payload): void
    {
        $this->expectException(ScheduleException::class);

        Schedule::fromArray($payload);
    }

    private static function at(string $utc): int
    {
        return (new \DateTimeImmutable($utc, new \DateTimeZone('UTC')))->getTimestamp();
    }
}
