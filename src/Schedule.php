<?php

namespace Utopia\WAF;

use Utopia\WAF\Exception\Schedule as ScheduleException;

/**
 * When a rule is active: a set of days and an optional time-of-day window, read on the clock
 * of the schedule's timezone (UTC unless one is given).
 *
 * A window whose start is later than its end crosses midnight and belongs to the day it
 * starts on. Modes counted from an anchor date are inactive before that date. On a
 * daylight-saving change, a window inside the skipped hour opens once the clock lands past
 * it, and one inside the repeated hour is active both times that hour occurs.
 */
final class Schedule
{
    public const MODE_DAILY = 'daily';
    public const MODE_WEEKLY = 'weekly';
    public const MODE_BIWEEKLY = 'biweekly';
    public const MODE_WEEKENDS = 'weekends';
    public const MODE_EVERY_N_DAYS = 'everyNDays';

    public const MODES = [
        self::MODE_DAILY,
        self::MODE_WEEKLY,
        self::MODE_BIWEEKLY,
        self::MODE_WEEKENDS,
        self::MODE_EVERY_N_DAYS,
    ];

    public const MIN_INTERVAL = 2;
    public const MAX_INTERVAL = 365;

    public const DEFAULT_TIMEZONE = 'UTC';

    private const KEYS = ['mode', 'days', 'interval', 'anchor', 'startTime', 'endTime', 'timezone'];
    private const SECONDS_PER_DAY = 86400;

    /**
     * @param array<int> $days ISO weekdays, 1 = Monday to 7 = Sunday, sorted
     */
    private function __construct(
        private readonly string $mode,
        private readonly array $days,
        private readonly ?int $interval,
        private readonly ?string $anchor,
        private readonly ?string $startTime,
        private readonly ?string $endTime,
        private readonly int $weekdayMask,
        private readonly ?int $anchorDay,
        private readonly ?int $startMinute,
        private readonly ?int $endMinute,
        private readonly ?\DateTimeZone $zone,
    ) {
    }

    /**
     * @param array<mixed> $payload
     *
     * @throws ScheduleException when the payload is not a valid schedule
     */
    public static function fromArray(array $payload): self
    {
        $unknown = \array_diff(\array_map(strval(...), \array_keys($payload)), self::KEYS);
        if ($unknown !== []) {
            throw new ScheduleException('Unknown schedule key: ' . \implode(', ', $unknown) . '.');
        }

        $mode = $payload['mode'] ?? null;
        if (!\is_string($mode) || !\in_array($mode, self::MODES, true)) {
            throw new ScheduleException('Schedule mode must be one of: ' . \implode(', ', self::MODES) . '.');
        }

        $usesDays = $mode === self::MODE_WEEKLY || $mode === self::MODE_BIWEEKLY;
        $usesInterval = $mode === self::MODE_EVERY_N_DAYS;
        $usesAnchor = $mode === self::MODE_BIWEEKLY || $mode === self::MODE_EVERY_N_DAYS;

        $days = self::parseDays($payload['days'] ?? null, $mode, $usesDays);
        $interval = self::parseInterval($payload['interval'] ?? null, $mode, $usesInterval);
        [$anchor, $anchorDay] = self::parseAnchor($payload['anchor'] ?? null, $mode, $usesAnchor);

        $startTime = $payload['startTime'] ?? null;
        $endTime = $payload['endTime'] ?? null;
        if (($startTime === null) !== ($endTime === null)) {
            throw new ScheduleException('Schedule startTime and endTime must be set together.');
        }

        $startMinute = $startTime === null ? null : self::parseTime($startTime, 'startTime');
        $endMinute = $endTime === null ? null : self::parseTime($endTime, 'endTime');
        if ($startMinute !== null && $startMinute === $endMinute) {
            throw new ScheduleException('Schedule startTime and endTime must differ; leave both out for the whole day.');
        }

        $zone = self::parseTimezone($payload['timezone'] ?? null);

        $weekdayMask = 0;
        foreach ($days as $day) {
            $weekdayMask |= 1 << $day;
        }

        return new self(
            $mode,
            $days,
            $interval,
            $anchor,
            \is_string($startTime) ? $startTime : null,
            \is_string($endTime) ? $endTime : null,
            $weekdayMask,
            $anchorDay,
            $startMinute,
            $endMinute,
            $zone,
        );
    }

    /**
     * @return array{mode: string, days?: array<int>, interval?: int, anchor?: string, startTime?: string, endTime?: string, timezone?: string}
     */
    public function toArray(): array
    {
        $schedule = ['mode' => $this->mode];

        if ($this->days !== []) {
            $schedule['days'] = $this->days;
        }
        if ($this->interval !== null) {
            $schedule['interval'] = $this->interval;
        }
        if ($this->anchor !== null) {
            $schedule['anchor'] = $this->anchor;
        }
        if ($this->startTime !== null && $this->endTime !== null) {
            $schedule['startTime'] = $this->startTime;
            $schedule['endTime'] = $this->endTime;
        }
        if ($this->zone !== null) {
            $schedule['timezone'] = $this->zone->getName();
        }

        return $schedule;
    }

    public function isActiveAt(int $timestamp): bool
    {
        // Seconds since 1970-01-01 00:00 on the schedule's local clock.
        $local = $this->zone === null
            ? $timestamp
            : $timestamp + $this->zone->getOffset(new \DateTimeImmutable('@' . $timestamp));

        $day = \intdiv($local, self::SECONDS_PER_DAY);
        $secondOfDay = $local % self::SECONDS_PER_DAY;
        if ($secondOfDay < 0) {
            $day--;
            $secondOfDay += self::SECONDS_PER_DAY;
        }
        $minute = \intdiv($secondOfDay, 60);

        if ($this->startMinute === null || $this->endMinute === null) {
            return $this->coversDay($day);
        }

        if ($this->startMinute < $this->endMinute) {
            return $minute >= $this->startMinute && $minute < $this->endMinute && $this->coversDay($day);
        }

        // Crosses midnight: the late part belongs to today, the early part to yesterday.
        return ($minute >= $this->startMinute && $this->coversDay($day))
            || ($minute < $this->endMinute && $this->coversDay($day - 1));
    }

    /**
     * @param int $day days since 1970-01-01 on the schedule's local clock
     */
    private function coversDay(int $day): bool
    {
        return match ($this->mode) {
            self::MODE_DAILY => true,
            self::MODE_WEEKENDS => self::isoWeekday($day) >= 6,
            self::MODE_WEEKLY => $this->isSelectedWeekday($day),
            self::MODE_BIWEEKLY => $day >= $this->anchorDay
                && $this->isSelectedWeekday($day)
                && \intdiv(self::weekStart($day) - self::weekStart((int) $this->anchorDay), 7) % 2 === 0,
            self::MODE_EVERY_N_DAYS => $day >= $this->anchorDay
                && ($day - (int) $this->anchorDay) % (int) $this->interval === 0,
            default => false,
        };
    }

    private function isSelectedWeekday(int $day): bool
    {
        return ($this->weekdayMask & (1 << self::isoWeekday($day))) !== 0;
    }

    /**
     * 1970-01-01 was a Thursday (ISO 4).
     */
    private static function isoWeekday(int $day): int
    {
        return (($day + 3) % 7 + 7) % 7 + 1;
    }

    private static function weekStart(int $day): int
    {
        return $day - (self::isoWeekday($day) - 1);
    }

    /**
     * @return array<int>
     */
    private static function parseDays(mixed $days, string $mode, bool $required): array
    {
        if (!$required) {
            if ($days !== null) {
                throw new ScheduleException("Schedule days are not used by mode {$mode}.");
            }

            return [];
        }

        if (!\is_array($days) || $days === [] || !\array_is_list($days)) {
            throw new ScheduleException("Schedule mode {$mode} needs a non-empty list of days.");
        }

        foreach ($days as $day) {
            if (!\is_int($day) || $day < 1 || $day > 7) {
                throw new ScheduleException('Schedule days must be ISO weekdays from 1 (Monday) to 7 (Sunday).');
            }
        }

        if (\count(\array_unique($days)) !== \count($days)) {
            throw new ScheduleException('Schedule days must not repeat.');
        }

        \sort($days);

        return $days;
    }

    private static function parseInterval(mixed $interval, string $mode, bool $required): ?int
    {
        if (!$required) {
            if ($interval !== null) {
                throw new ScheduleException("Schedule interval is not used by mode {$mode}.");
            }

            return null;
        }

        if (!\is_int($interval) || $interval < self::MIN_INTERVAL || $interval > self::MAX_INTERVAL) {
            throw new ScheduleException('Schedule interval must be a whole number of days from ' . self::MIN_INTERVAL . ' to ' . self::MAX_INTERVAL . '.');
        }

        return $interval;
    }

    /**
     * @return array{0: ?string, 1: ?int} the anchor date and its day number since 1970-01-01
     */
    private static function parseAnchor(mixed $anchor, string $mode, bool $required): array
    {
        if (!$required) {
            if ($anchor !== null) {
                throw new ScheduleException("Schedule anchor is not used by mode {$mode}.");
            }

            return [null, null];
        }

        // Shape first: the date parser throws on a null byte instead of returning false.
        $date = \is_string($anchor) && \preg_match('/^\d{4}-\d{2}-\d{2}\z/', $anchor) === 1
            ? \DateTimeImmutable::createFromFormat('!Y-m-d', $anchor, new \DateTimeZone('UTC'))
            : false;

        if ($date === false || $date->format('Y-m-d') !== $anchor) {
            throw new ScheduleException("Schedule mode {$mode} needs an anchor date formatted as YYYY-MM-DD.");
        }

        return [$anchor, \intdiv($date->getTimestamp(), self::SECONDS_PER_DAY)];
    }

    /**
     * @return \DateTimeZone|null null for UTC, which needs no offset lookup
     */
    private static function parseTimezone(mixed $timezone): ?\DateTimeZone
    {
        if ($timezone === null || $timezone === self::DEFAULT_TIMEZONE) {
            return null;
        }

        /** @var array<string, true>|null $identifiers */
        static $identifiers = null;
        $identifiers ??= \array_fill_keys(\DateTimeZone::listIdentifiers(\DateTimeZone::ALL_WITH_BC), true);

        if (!\is_string($timezone) || !isset($identifiers[$timezone])) {
            throw new ScheduleException('Schedule timezone must be an IANA timezone name such as Europe/Berlin.');
        }

        return new \DateTimeZone($timezone);
    }

    private static function parseTime(mixed $time, string $field): int
    {
        if (!\is_string($time) || \preg_match('/^([01]\d|2[0-3]):([0-5]\d)\z/', $time, $parts) !== 1) {
            throw new ScheduleException("Schedule {$field} must be a time formatted as HH:MM, on the schedule's timezone clock (UTC unless a timezone is given).");
        }

        return (int) $parts[1] * 60 + (int) $parts[2];
    }
}
