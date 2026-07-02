<?php

namespace Utopia\WAF\Challenge;

/**
 * Issues proof-of-work challenges.
 *
 * The client must find a `solution` such that
 * `sha256(nonce . '.' . solution)` has at least `difficulty` leading zero bits.
 * The nonce is a signed, short-lived, context-bound token — issuance is stateless
 * and verification (see Verifier) is a single hash.
 */
final class Issuer
{
    public const DIFFICULTY_MIN = 16;
    public const DIFFICULTY_DEFAULT = 20;
    public const DIFFICULTY_MAX = 24;

    public const NONCE_TTL = 120;

    public const ALGORITHM = 'sha256';

    public function __construct(private readonly Signer $signer)
    {
    }

    /**
     * Mint a challenge for the given context.
     *
     * `expiresAt` is an absolute timestamp for convenience; `expiresIn` is the
     * same deadline expressed relative to issuance, which clients should prefer
     * so a skewed local clock does not shorten or extend the solve window.
     *
     * @return array{nonce: string, difficulty: int, algorithm: string, expiresAt: int, expiresIn: int}
     */
    public function issue(Context $context, int $difficulty = self::DIFFICULTY_DEFAULT): array
    {
        $difficulty = \max(self::DIFFICULTY_MIN, \min(self::DIFFICULTY_MAX, $difficulty));

        $issuedAt = \time();
        $expiresAt = $issuedAt + self::NONCE_TTL;

        $nonce = $this->signer->sign([
            'typ' => 'pow',
            'ver' => 1,
            'pid' => $context->projectId,
            'aud' => $context->audience,
            'iph' => $this->signer->fingerprintIp($context->ip),
            'dif' => $difficulty,
            'iat' => $issuedAt,
            'exp' => $expiresAt,
            'rnd' => \bin2hex(\random_bytes(16)),
        ]);

        return [
            'nonce' => $nonce,
            'difficulty' => $difficulty,
            'algorithm' => self::ALGORITHM,
            'expiresAt' => $expiresAt,
            'expiresIn' => self::NONCE_TTL,
        ];
    }
}
