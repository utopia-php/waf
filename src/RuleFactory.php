<?php

namespace Utopia\WAF;

use Utopia\WAF\Exception\Condition as ConditionException;
use Utopia\WAF\Rules\Bypass;
use Utopia\WAF\Rules\Challenge;
use Utopia\WAF\Rules\Deny;
use Utopia\WAF\Rules\RateLimit;
use Utopia\WAF\Rules\Redirect;

class RuleFactory
{
    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): Rule
    {
        $action = \array_key_exists('action', $payload) ? $payload['action'] : '';
        if (!\is_string($action)) {
            throw new \InvalidArgumentException('Invalid rule action definition.');
        }

        $conditions = \array_key_exists('conditions', $payload) ? $payload['conditions'] : [];
        if (!\is_array($conditions)) {
            throw new \InvalidArgumentException('Invalid rule conditions definition.');
        }

        $config = \array_key_exists('config', $payload) ? $payload['config'] : [];
        if (!\is_array($config)) {
            throw new \InvalidArgumentException('Invalid rule config definition.');
        }

        return self::create($action, $conditions, $config);
    }

    /**
     * @param array<Condition|array<string, mixed>> $conditions
     * @param array<string, mixed> $config
     */
    public static function create(string $action, array $conditions = [], array $config = []): Rule
    {
        self::validateConditions($conditions);

        return match ($action) {
            Rule::ACTION_BYPASS => new Bypass($conditions),
            Rule::ACTION_DENY => new Deny($conditions),
            Rule::ACTION_CHALLENGE => new Challenge(
                $conditions,
                self::stringConfig($config, 'type', Challenge::TYPE_CAPTCHA)
            ),
            Rule::ACTION_RATE_LIMIT => new RateLimit(
                $conditions,
                self::intConfig($config, 'limit', 100),
                self::intConfig($config, 'interval', 3600)
            ),
            Rule::ACTION_REDIRECT => new Redirect(
                $conditions,
                self::stringConfig($config, 'location', '/'),
                self::intConfig($config, 'statusCode', 302)
            ),
            default => throw new \InvalidArgumentException('Unsupported rule action: ' . $action),
        };
    }

    /**
     * @param array<Condition|array<string, mixed>> $conditions
     */
    private static function validateConditions(array $conditions): void
    {
        foreach ($conditions as $condition) {
            if ($condition instanceof Condition) {
                continue;
            }

            if (!\is_array($condition)) {
                throw new \InvalidArgumentException('Invalid rule condition definition.');
            }

            try {
                Condition::fromArray($condition);
            } catch (ConditionException $exception) {
                throw new \InvalidArgumentException('Invalid rule condition definition.', previous: $exception);
            }
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function stringConfig(array $config, string $key, string $default): string
    {
        if (!\array_key_exists($key, $config)) {
            return $default;
        }

        $value = $config[$key];
        if (!\is_string($value)) {
            throw new \InvalidArgumentException("Invalid rule config value for {$key}.");
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function intConfig(array $config, string $key, int $default): int
    {
        if (!\array_key_exists($key, $config)) {
            return $default;
        }

        $value = $config[$key];
        if (!\is_int($value)) {
            throw new \InvalidArgumentException("Invalid rule config value for {$key}.");
        }

        return $value;
    }
}
