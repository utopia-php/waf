<?php

namespace Utopia\WAF\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Exception\Schedule as ScheduleException;
use Utopia\WAF\Schedule;
use Utopia\WAF\Validator\Schedule as ScheduleValidator;

/**
 * Random schedules built from awkward values. Whatever comes in, the only failure allowed out is
 * Exception\Schedule, so bad input is a 400 and never a 500.
 */
class ScheduleFuzzTest extends TestCase
{
    private const CASES = 20000;
    private const SEED = 7254;

    private const KEYS = ['mode', 'days', 'interval', 'anchor', 'startTime', 'endTime', 'timezone', 0, '', 'unknown'];

    public function testOnlyScheduleExceptionsComeOut(): void
    {
        \mt_srand(self::SEED);
        $values = self::values();
        $accepted = 0;

        for ($case = 0; $case < self::CASES; $case++) {
            $payload = self::payload($values);

            try {
                $schedule = Schedule::fromArray($payload);
            } catch (ScheduleException) {
                $this->assertFalse((new ScheduleValidator())->isValid($payload), 'validator accepted what fromArray rejected: ' . self::show($payload));
                continue;
            } catch (\Throwable $e) {
                $this->fail(\get_class($e) . ': ' . $e->getMessage() . ' for ' . self::show($payload));
            }

            $accepted++;
            $this->assertTrue((new ScheduleValidator())->isValid($payload), 'validator rejected what fromArray accepted: ' . self::show($payload));

            try {
                $schedule->isActiveAt(\mt_rand(-2_000_000_000, 4_000_000_000));
            } catch (\Throwable $e) {
                $this->fail('isActiveAt threw ' . \get_class($e) . ': ' . $e->getMessage() . ' for ' . self::show($payload));
            }

            $stored = $schedule->toArray();
            $this->assertSame($stored, Schedule::fromArray($stored)->toArray(), 'toArray did not round-trip for ' . self::show($payload));
        }

        // A generator that only produced rejects would test nothing past the parser.
        $this->assertGreaterThan(self::CASES / 50, $accepted, 'too few random schedules were valid');
    }

    public function testValidatorNeverThrows(): void
    {
        \mt_srand(self::SEED + 1);
        $values = self::values();
        $validator = new ScheduleValidator();

        for ($case = 0; $case < self::CASES; $case++) {
            $value = \mt_rand(0, 9) === 0 ? $values[\array_rand($values)] : self::payload($values);

            try {
                $validator->isValid($value);
            } catch (\Throwable $e) {
                $this->fail(\get_class($e) . ': ' . $e->getMessage() . ' for ' . self::show($value));
            }
        }

        $this->addToAssertionCount(self::CASES);
    }

    /**
     * @return list<mixed>
     */
    private static function values(): array
    {
        return [
            null, true, false,
            0, 1, 2, 3, 5, 7, 8, -1, 365, 366, PHP_INT_MAX, PHP_INT_MIN,
            1.0, 1.5, -0.0, NAN, INF,
            '', ' ', '0', '1', "\0", "\0\0", "\n", 'é', '🙂',
            'daily', 'weekly', 'biweekly', 'weekends', 'everyNDays', 'DAILY',
            '00:00', '09:00', '23:59', '24:00', '9:00', "09:00\0", "\00009:00", '09:00:00',
            '2026-11-02', '2028-02-29', '2027-02-29', '0000-01-01', '9999-12-31', '-2026-01-01', '+2026-01-01',
            "2026-11-02\0", "\0002026-11-02", "2026-11\0-02", '2026-11-02 ', '2026-11-02T00:00:00Z', '２０２６-11-02',
            'UTC', 'Asia/Kolkata', 'Europe/Berlin', 'Etc/GMT+5', 'EST', '+05:30', "Asia/Kolkata\0", 'asia/kolkata',
            [], [1], [1, 5], [7, 1], [0], [8], [1, 1], ['1'], [1.0], [null], [[1]], ['a' => 1], [PHP_INT_MAX],
            \range(1, 7), \array_fill(0, 50, 1),
            new \stdClass(),
        ];
    }

    /**
     * Half the time a well-formed schedule with at most one field swapped for an awkward value, so
     * plenty get past validation into isActiveAt(); otherwise random keys and values.
     *
     * @param list<mixed> $values
     * @return array<mixed>
     */
    private static function payload(array $values): array
    {
        if (\mt_rand(0, 1) === 0) {
            $payload = self::wellFormed();
            if (\mt_rand(0, 1) === 0) {
                $payload[self::KEYS[\array_rand(self::KEYS)]] = $values[\array_rand($values)];
            }

            return $payload;
        }

        $payload = [];
        foreach (self::KEYS as $key) {
            if (\mt_rand(0, 2) === 0) {
                $payload[$key] = $values[\array_rand($values)];
            }
        }

        if (\mt_rand(0, 3) !== 0) {
            $payload['mode'] = Schedule::MODES[\array_rand(Schedule::MODES)];
        }

        return $payload;
    }

    /**
     * @return array<string, mixed>
     */
    private static function wellFormed(): array
    {
        $mode = Schedule::MODES[\array_rand(Schedule::MODES)];
        $payload = ['mode' => $mode];

        if ($mode === Schedule::MODE_WEEKLY || $mode === Schedule::MODE_BIWEEKLY) {
            $days = \range(1, 7);
            \shuffle($days);
            $payload['days'] = \array_slice($days, 0, \mt_rand(1, 7));
        }
        if ($mode === Schedule::MODE_EVERY_N_DAYS) {
            $payload['interval'] = \mt_rand(Schedule::MIN_INTERVAL, Schedule::MAX_INTERVAL);
        }
        if ($mode === Schedule::MODE_BIWEEKLY || $mode === Schedule::MODE_EVERY_N_DAYS) {
            $payload['anchor'] = \sprintf('%04d-%02d-%02d', \mt_rand(1900, 2100), \mt_rand(1, 12), \mt_rand(1, 28));
        }
        if (\mt_rand(0, 1) === 0) {
            $start = \mt_rand(0, 1439);
            $end = ($start + \mt_rand(1, 1439)) % 1440;
            $payload['startTime'] = \sprintf('%02d:%02d', \intdiv($start, 60), $start % 60);
            $payload['endTime'] = \sprintf('%02d:%02d', \intdiv($end, 60), $end % 60);
        }
        if (\mt_rand(0, 1) === 0) {
            $payload['timezone'] = ['UTC', 'Asia/Kolkata', 'Europe/Berlin', 'America/New_York', 'Australia/Lord_Howe', 'Pacific/Chatham'][\mt_rand(0, 5)];
        }

        return $payload;
    }

    private static function show(mixed $value): string
    {
        return \json_encode($value, JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE) ?: \var_export($value, true);
    }
}
