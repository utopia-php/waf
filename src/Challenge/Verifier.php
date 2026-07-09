<?php

namespace Utopia\WAF\Challenge;

/**
 * Verifies a silent-challenge nonce's integrity: authentic, unexpired, and bound
 * to the same context. There is no proof-of-work — the silent tier's verdict comes
 * from scoring the attested signals ({@see SilentChallenge}), not from a solved
 * puzzle. This class answers only "is this nonce a genuine, live challenge for this
 * client?"; the scoring engine decides human-vs-bot.
 */
final class Verifier
{
    /** Clock-skew tolerance, in seconds, applied to nonce timestamps. */
    public const LEEWAY = 5;

    public function __construct(private readonly Signer $signer)
    {
    }

    /**
     * Whether `$nonce` is an authentic, unexpired silent-challenge nonce bound to
     * `$context` (project + audience + IP prefix). Stateless.
     */
    public function verify(string $nonce, Context $context): bool
    {
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

        return \hash_equals($expectedIp, (string) ($claims['iph'] ?? ''));
    }
}
