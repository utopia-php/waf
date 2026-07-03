<?php

namespace Utopia\WAF\Challenge;

/**
 * Verifies challenge solutions in constant work (one hash).
 *
 * A solution is accepted only when the nonce is authentic, unexpired, bound to
 * the same context, and `sha256(nonce . '.' . solution)` meets the difficulty
 * baked into the nonce.
 */
final class Verifier
{
    /** Maximum solution length accepted, guarding the verify hash against oversized input. */
    public const SOLUTION_MAX_LENGTH = 64;

    /** Clock-skew tolerance, in seconds, applied to nonce timestamps. */
    public const LEEWAY = 5;

    public function __construct(private readonly Signer $signer)
    {
    }

    public function verify(string $nonce, string $solution, Context $context): bool
    {
        if ($solution === '' || \strlen($solution) > self::SOLUTION_MAX_LENGTH) {
            return false;
        }

        $claims = $this->signer->parse($nonce);
        if ($claims === null || ($claims['typ'] ?? null) !== 'challenge') {
            return false;
        }

        $now = \time();
        $expiresAt = (int) ($claims['exp'] ?? 0);
        $issuedAt = (int) ($claims['iat'] ?? PHP_INT_MAX);
        if ($expiresAt < $now - self::LEEWAY || $issuedAt > $now + self::LEEWAY) {
            return false;
        }

        if (($claims['pid'] ?? null) !== $context->projectId || ($claims['aud'] ?? null) !== $context->audience) {
            return false;
        }

        $kid = \is_int($claims['kid'] ?? null) ? $claims['kid'] : null;
        $expectedIp = $this->signer->fingerprintIp($context->ip, $kid);
        if (!\hash_equals($expectedIp, (string) ($claims['iph'] ?? ''))) {
            return false;
        }

        $difficulty = (int) ($claims['dif'] ?? 0);
        if ($difficulty <= 0) {
            return false;
        }

        $digest = \hash(Issuer::ALGORITHM, $nonce . '.' . $solution, true);

        return self::leadingZeroBits($digest) >= $difficulty;
    }

    /**
     * Count leading zero bits across the raw (binary) digest.
     */
    private static function leadingZeroBits(string $digest): int
    {
        $bits = 0;
        $length = \strlen($digest);

        for ($i = 0; $i < $length; $i++) {
            $byte = \ord($digest[$i]);

            if ($byte === 0) {
                $bits += 8;

                continue;
            }

            for ($mask = 0x80; $mask > 0; $mask >>= 1) {
                if (($byte & $mask) !== 0) {
                    return $bits;
                }

                $bits++;
            }
        }

        return $bits;
    }
}
