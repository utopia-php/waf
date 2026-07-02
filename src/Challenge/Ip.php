<?php

namespace Utopia\WAF\Challenge;

/**
 * Network-prefix helper for challenge binding.
 *
 * Clearances bind to an IP prefix rather than an exact address so a client
 * behind carrier-grade NAT or mobile IP churn is not re-challenged on every
 * request, while a token still cannot travel to a different network.
 */
final class Ip
{
    /**
     * Reduce an address to its network prefix: /24 for IPv4, /64 for IPv6.
     *
     * Returns the input unchanged when it is not a parseable address, so an
     * unexpected value still binds consistently (to itself) rather than throwing.
     */
    public static function prefix(string $ip): string
    {
        $packed = @\inet_pton($ip);
        if ($packed === false) {
            return $ip;
        }

        $length = \strlen($packed);

        if ($length === 4) {
            $masked = \substr($packed, 0, 3) . "\0";

            return (string) \inet_ntop($masked);
        }

        if ($length === 16) {
            $masked = \substr($packed, 0, 8) . \str_repeat("\0", 8);

            return (string) \inet_ntop($masked);
        }

        return $ip;
    }
}
