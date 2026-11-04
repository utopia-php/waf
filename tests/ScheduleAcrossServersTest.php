<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Utopia\WAF\Exception\Schedule as ScheduleException;
use Utopia\WAF\Schedule;
use Utopia\WAF\Validator\Schedule as ScheduleValidator;

/**
 * A schedule is written by a user in one zone, validated and stored by a cloud server set
 * to another, and evaluated by an edge server set to a third. Every hop must agree.
 *
 * @phpstan-type Unzoned array{mode: string, days?: list<int>, interval?: int, anchor?: string, startTime?: string, endTime?: string}
 * @phpstan-type Zoned array{mode: string, days?: list<int>, interval?: int, anchor?: string, startTime?: string, endTime?: string, timezone: string}
 */
class ScheduleAcrossServersTest extends TestCase
{
    /**
     * Zones users schedule in: whole, half and quarter hours, both hemispheres' DST,
     * a 30-minute DST shift (Lord Howe), and the two ends of the offset range.
     */
    private const USER_ZONES = [
        'UTC',
        'Asia/Kolkata',
        'Asia/Kathmandu',
        'America/New_York',
        'Europe/Berlin',
        'Australia/Sydney',
        'Australia/Lord_Howe',
        'Pacific/Chatham',
        'Pacific/Kiritimati',
        'Pacific/Pago_Pago',
    ];

    /**
     * What `date.timezone` a cloud or edge server might be set to.
     */
    private const SERVER_ZONES = ['UTC', 'Europe/Berlin', 'Asia/Kolkata', 'America/Los_Angeles', 'Pacific/Kiritimati'];

    /**
     * @return iterable<string, array{Unzoned}>
     */
    public static function schedules(): iterable
    {
        yield 'daily office hours' => [['mode' => 'daily', 'startTime' => '09:00', 'endTime' => '17:00']];
        yield 'weekly overnight' => [['mode' => 'weekly', 'days' => [5, 6], 'startTime' => '22:00', 'endTime' => '06:00']];
        yield 'weekends all day' => [['mode' => 'weekends']];
        yield 'weekends overnight' => [['mode' => 'weekends', 'startTime' => '23:00', 'endTime' => '01:00']];
        yield 'biweekly mornings' => [['mode' => 'biweekly', 'days' => [1, 3], 'anchor' => '2026-03-02', 'startTime' => '02:00', 'endTime' => '04:00']];
        yield 'every 3 days' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-03-01']];
        yield 'every 5 nights' => [['mode' => 'everyNDays', 'interval' => 5, 'anchor' => '2026-03-01', 'startTime' => '23:30', 'endTime' => '00:30']];
    }

    /**
     * Each schedule in each user zone, against an independent calendar computed with DateTime.
     *
     * @return iterable<string, array{Zoned}>
     */
    public static function zonedSchedules(): iterable
    {
        foreach (self::schedules() as $name => [$schedule]) {
            foreach (self::USER_ZONES as $zone) {
                yield "{$name} in {$zone}" => [$schedule + ['timezone' => $zone]];
            }
        }
    }

    /**
     * @param Zoned $payload
     */
    #[DataProvider('zonedSchedules')]
    public function testMatchesTheUsersLocalCalendar(array $payload): void
    {
        $schedule = Schedule::fromArray($payload);

        foreach (self::instants($payload['timezone']) as $timestamp) {
            $this->assertSame(
                self::expectedOnLocalCalendar($payload, $timestamp),
                $schedule->isActiveAt($timestamp),
                self::describe($payload, $timestamp),
            );
        }
    }

    /**
     * Validated and stored on a cloud server in one zone, rebuilt and evaluated on an edge server
     * in another: the stored form and every answer are the same as on a UTC server.
     *
     * @param Zoned $payload
     */
    #[DataProvider('zonedSchedules')]
    public function testCloudAndEdgeServerZonesDoNotChangeTheOutcome(array $payload): void
    {
        $reference = Schedule::fromArray($payload);
        $expectedStored = \json_encode($reference->toArray(), JSON_THROW_ON_ERROR);
        $instants = self::instants($payload['timezone'], 97 * 60, 600);
        $original = \date_default_timezone_get();

        try {
            // The cloud server's zone can only show up in what it stores, so pin that first.
            foreach (self::SERVER_ZONES as $cloudZone) {
                \date_default_timezone_set($cloudZone);
                $this->assertTrue((new ScheduleValidator())->isValid($payload), "cloud in {$cloudZone} rejected it");
                $this->assertSame($expectedStored, \json_encode(Schedule::fromArray($payload)->toArray(), JSON_THROW_ON_ERROR), "cloud in {$cloudZone} stored it differently");
            }

            foreach (self::SERVER_ZONES as $edgeZone) {
                \date_default_timezone_set($edgeZone);
                /** @var array<string, mixed> $stored */
                $stored = \json_decode($expectedStored, true, 512, JSON_THROW_ON_ERROR);
                $edge = Schedule::fromArray($stored);

                foreach ($instants as $timestamp) {
                    if ($edge->isActiveAt($timestamp) !== $reference->isActiveAt($timestamp)) {
                        $this->fail("edge in {$edgeZone} disagrees at " . self::describe($payload, $timestamp));
                    }
                }
            }
        } finally {
            \date_default_timezone_set($original);
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function invalidPayloads(): iterable
    {
        yield 'unknown zone' => [['mode' => 'daily', 'timezone' => 'Asia/Atlantis']];
        yield 'fixed offset zone' => [['mode' => 'daily', 'timezone' => '-03:00']];
        yield 'anchor that does not exist' => [['mode' => 'everyNDays', 'interval' => 3, 'anchor' => '2026-02-30', 'timezone' => 'Asia/Kolkata']];
        yield 'hour 24' => [['mode' => 'daily', 'startTime' => '24:00', 'endTime' => '01:00', 'timezone' => 'Europe/Berlin']];
        yield 'start equals end' => [['mode' => 'daily', 'startTime' => '02:30', 'endTime' => '02:30', 'timezone' => 'Europe/Berlin']];
    }

    /**
     * @param array<string, mixed> $payload
     */
    #[DataProvider('invalidPayloads')]
    public function testEveryServerZoneRejectsTheSameInput(array $payload): void
    {
        $original = \date_default_timezone_get();
        $messages = [];

        try {
            foreach (self::SERVER_ZONES as $zone) {
                \date_default_timezone_set($zone);
                $validator = new ScheduleValidator();
                $this->assertFalse($validator->isValid($payload), "accepted on a server in {$zone}");
                $messages[$validator->getDescription()] = true;

                try {
                    Schedule::fromArray($payload);
                    $this->fail("built on a server in {$zone}");
                } catch (ScheduleException) {
                }
            }
        } finally {
            \date_default_timezone_set($original);
        }

        $this->assertCount(1, $messages, 'servers in different zones gave different errors');
    }

    /**
     * Every $step seconds over 2026 (an odd number of minutes, so instants drift across the hour),
     * plus every $nearChange seconds for three hours either side of each daylight-saving change.
     *
     * @return array<int>
     */
    private static function instants(string $zone, int $step = 37 * 60, int $nearChange = 60): array
    {
        $start = self::utc('2026-01-01 00:00');
        $end = self::utc('2027-01-01 00:00');

        $instants = [];
        for ($t = $start; $t < $end; $t += $step) {
            $instants[] = $t;
        }

        $transitions = (new \DateTimeZone($zone))->getTransitions($start, $end) ?: [];
        foreach (\array_slice($transitions, 1) as $transition) {
            for ($t = $transition['ts'] - 3 * 3600; $t <= $transition['ts'] + 3 * 3600; $t += $nearChange) {
                $instants[] = $t;
            }
        }

        return $instants;
    }

    /**
     * The same rules worked out on DateTime's calendar in the schedule's zone, as a cross-check
     * on Schedule's integer arithmetic.
     *
     * @param Zoned $payload
     */
    private static function expectedOnLocalCalendar(array $payload, int $timestamp): bool
    {
        $utc = new \DateTimeZone('UTC');
        $local = (new \DateTimeImmutable('@' . $timestamp))->setTimezone(new \DateTimeZone($payload['timezone']));
        $today = new \DateTimeImmutable($local->format('Y-m-d'), $utc);
        $minute = (int) $local->format('G') * 60 + (int) $local->format('i');

        $covers = static function (\DateTimeImmutable $date) use ($payload, $utc): bool {
            $weekday = (int) $date->format('N');
            $anchor = isset($payload['anchor']) ? new \DateTimeImmutable($payload['anchor'], $utc) : null;
            $sinceAnchor = $anchor === null ? 0 : (int) $anchor->diff($date)->format('%r%a');
            $days = $payload['days'] ?? [];

            return match ($payload['mode']) {
                'daily' => true,
                'weekends' => $weekday >= 6,
                'weekly' => \in_array($weekday, $days, true),
                'biweekly' => $sinceAnchor >= 0
                    && \in_array($weekday, $days, true)
                    && \intdiv((int) $anchor?->modify('monday this week')->diff($date->modify('monday this week'))->format('%a'), 7) % 2 === 0,
                'everyNDays' => $sinceAnchor >= 0 && $sinceAnchor % ($payload['interval'] ?? 1) === 0,
                default => false,
            };
        };

        if (!isset($payload['startTime'], $payload['endTime'])) {
            return $covers($today);
        }

        [$startHour, $startMinute] = \array_map(intval(...), \explode(':', $payload['startTime']));
        [$endHour, $endMinute] = \array_map(intval(...), \explode(':', $payload['endTime']));
        $start = $startHour * 60 + $startMinute;
        $end = $endHour * 60 + $endMinute;

        if ($start < $end) {
            return $minute >= $start && $minute < $end && $covers($today);
        }

        return ($minute >= $start && $covers($today))
            || ($minute < $end && $covers($today->modify('-1 day')));
    }

    /**
     * @param Zoned $payload
     */
    private static function describe(array $payload, int $timestamp): string
    {
        $local = (new \DateTimeImmutable('@' . $timestamp))->setTimezone(new \DateTimeZone($payload['timezone']));

        return \gmdate('Y-m-d H:i', $timestamp) . ' UTC (' . $local->format('D Y-m-d H:i T') . ') for ' . \json_encode($payload);
    }

    private static function utc(string $time): int
    {
        return (new \DateTimeImmutable($time, new \DateTimeZone('UTC')))->getTimestamp();
    }
}
