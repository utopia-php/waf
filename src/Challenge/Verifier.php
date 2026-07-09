<?php

namespace Utopia\WAF\Challenge;

/**
 * Verifies challenge solutions in bounded work (one proof-of-work digest).
 *
 * A solution is accepted only when the nonce is authentic, unexpired, bound to
 * the same context, and the proof-of-work digest of `nonce . '.' . solution`
 * meets the difficulty baked into the nonce. The digest is plain SHA-256, or the
 * memory-hard variant when the nonce carries a `mem` cost (see {@see SilentChallenge}).
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

        // Memory-hard cost, when the nonce carries one. The nonce is HMAC-signed,
        // so `mem` cannot be forged; the clamp is a defensive bound on verify work.
        $memory = (int) ($claims['mem'] ?? 0);
        if ($memory > 0) {
            $memory = \min($memory, Issuer::MEMORY_MAX);
        }

        return SilentChallenge::meets($nonce . '.' . $solution, $difficulty, $memory);
    }
}
