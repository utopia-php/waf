<?php

namespace Utopia\WAF\Attributes;

use Utopia\WAF\Attribute;
use Utopia\WAF\Condition;

/**
 * IP
 *
 * Lets IP-valued attributes match against CIDR blocks alongside plain IPs,
 * e.g. equal('ip', ['203.0.113.10', '10.0.0.0/8']). Plain IP values fall
 * back to the default case-insensitive string equality.
 */
class IP implements Attribute
{
    public function compare(string $method, mixed $value, mixed $expected): ?bool
    {
        if ($method !== Condition::TYPE_EQUAL) {
            return null;
        }

        if (!\is_string($expected) || !self::isCidr($expected)) {
            return null;
        }

        if (!\is_string($value)) {
            return false;
        }

        return self::cidrContains($expected, $value);
    }

    public function validateValue(string $method, mixed $expected): ?string
    {
        if ($method !== Condition::TYPE_EQUAL && $method !== Condition::TYPE_NOT_EQUAL) {
            return null;
        }

        if (!\is_string($expected)) {
            return 'Value must be an IP address or CIDR block string.';
        }

        if (\filter_var($expected, FILTER_VALIDATE_IP) !== false || self::isCidr($expected)) {
            return null;
        }

        return "Value \"{$expected}\" is not a valid IP address or CIDR block.";
    }

    /**
     * Check whether a candidate string is a valid CIDR block ("<ip>/<prefix>").
     */
    private static function isCidr(string $candidate): bool
    {
        return self::parseCidr($candidate) !== null;
    }

    /**
     * Check whether an IP address falls inside a CIDR block.
     *
     * Malformed input or mismatched address families (IPv4 vs IPv6) never match.
     */
    private static function cidrContains(string $cidr, string $ip): bool
    {
        $parsed = self::parseCidr($cidr);
        if ($parsed === null) {
            return false;
        }

        [$network, $prefix] = $parsed;

        $address = @\inet_pton($ip);
        if ($address === false || \strlen($address) !== \strlen($network)) {
            return false;
        }

        $fullBytes = \intdiv($prefix, 8);
        if ($fullBytes > 0 && \substr($address, 0, $fullBytes) !== \substr($network, 0, $fullBytes)) {
            return false;
        }

        $remainingBits = $prefix % 8;
        if ($remainingBits === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainingBits) & 0xFF;

        return (\ord($address[$fullBytes]) & $mask) === (\ord($network[$fullBytes]) & $mask);
    }

    /**
     * Parse a CIDR block into its packed network address and prefix length.
     *
     * @return array{0: string, 1: int}|null
     */
    private static function parseCidr(string $candidate): ?array
    {
        $separator = \strpos($candidate, '/');
        if ($separator === false) {
            return null;
        }

        $ip = \substr($candidate, 0, $separator);
        $prefixPart = \substr($candidate, $separator + 1);

        if ($prefixPart === '' || !\ctype_digit($prefixPart)) {
            return null;
        }

        $network = @\inet_pton($ip);
        if ($network === false) {
            return null;
        }

        $prefix = (int) $prefixPart;
        $maxPrefix = \strlen($network) * 8;
        if ($prefix > $maxPrefix) {
            return null;
        }

        return [$network, $prefix];
    }
}
