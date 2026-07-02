<?php

namespace Utopia\WAF\Challenge;

/**
 * Mints and validates clearance tokens — proof that a challenge was solved.
 *
 * A clearance is a short-lived, context-bound signed token the client presents
 * on subsequent requests. Validation is a stateless signature + context check,
 * cheap enough for the request hot path and free of any shared server state.
 * The short TTL is the revocation model.
 */
final class Clearance
{
    public const TTL_MIN = 60;
    public const TTL_DEFAULT = 600;
    public const TTL_MAX = 3600;

    /** Clock-skew tolerance, in seconds, applied to token timestamps. */
    public const LEEWAY = 60;

    public function __construct(private readonly Signer $signer)
    {
    }

    public function issue(Context $context, int $ttl = self::TTL_DEFAULT): string
    {
        $ttl = \max(self::TTL_MIN, \min(self::TTL_MAX, $ttl));

        $issuedAt = \time();

        return $this->signer->sign([
            'typ' => 'clr',
            'ver' => 1,
            'pid' => $context->projectId,
            'aud' => $context->audience,
            'iph' => $this->signer->fingerprintIp($context->ip),
            'iat' => $issuedAt,
            'exp' => $issuedAt + $ttl,
        ]);
    }

    public function verify(string $token, Context $context): bool
    {
        if ($token === '') {
            return false;
        }

        $claims = $this->signer->parse($token);
        if ($claims === null || ($claims['typ'] ?? null) !== 'clr') {
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
