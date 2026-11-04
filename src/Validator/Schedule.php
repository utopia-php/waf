<?php

namespace Utopia\WAF\Validator;

use Utopia\Validator;
use Utopia\WAF\Exception\Schedule as ScheduleException;
use Utopia\WAF\Schedule as RuleSchedule;

class Schedule extends Validator
{
    private string $description = 'WAF rule schedule: mode (daily, weekly, biweekly, weekends or everyNDays), with days, interval and anchor as the mode needs, an optional startTime and endTime, and an optional IANA timezone (default UTC).';

    public function getDescription(): string
    {
        return $this->description;
    }

    public function isArray(): bool
    {
        return false;
    }

    public function getType(): string
    {
        return self::TYPE_OBJECT;
    }

    public function isValid($value): bool
    {
        if (!\is_array($value)) {
            $this->description = 'WAF rule schedule must be an object.';

            return false;
        }

        try {
            RuleSchedule::fromArray($value);
        } catch (ScheduleException $e) {
            $this->description = $e->getMessage();

            return false;
        }

        return true;
    }
}
