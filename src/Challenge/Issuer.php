<?php

namespace Utopia\WAF\Challenge;

/**
 * Issues silent-challenge nonces.
 *
 * The silent (invisible) tier does not ask the client to burn CPU. The nonce is a
 * signed, short-lived, context-bound anti-replay token: the client runs an
 * invisible script, collects environment/automation signals, and returns them
 * bound to this nonce as an attestation, which the engine then scores (see
 * {@see SilentChallenge}). Issuance is stateless.
 */
final class Issuer
{
    public const NONCE_TTL = 120;

    public function __construct(private readonly Signer $signer)
    {
    }

    /**
     * Mint a silent-challenge nonce for the given context.
     *
     * `expiresAt` is an absolute timestamp for convenience; `expiresIn` is the same
     * deadline relative to issuance, which clients should prefer so a skewed local
     * clock does not shorten or extend the attestation window.
     *
     * `$clearanceTtl`, when given, is carried inside the signed nonce (claim `ctl`)
     * so the verify endpoint — which only receives the nonce, never the matched
     * rule — can mint the clearance with the rule's configured lifetime. It is
     * authenticated by the nonce signature; read it back with
     * {@see self::clearanceTtl()} after verification.
     *
     * @return array{nonce: string, expiresAt: int, expiresIn: int}
     */
    public function issue(Context $context, ?int $clearanceTtl = null): array
    {
        $issuedAt = \time();
        $expiresAt = $issuedAt + self::NONCE_TTL;

        $claims = [
            'typ' => 'challenge',
            'ver' => 1,
            'pid' => $context->projectId,
            'aud' => $context->audience,
            'iph' => $this->signer->fingerprintIp($context->ip),
            'iat' => $issuedAt,
            'exp' => $expiresAt,
            'rnd' => \bin2hex(\random_bytes(16)),
        ];

        if ($clearanceTtl !== null) {
            $claims['ctl'] = $clearanceTtl;
        }

        $nonce = $this->signer->sign($claims);

        return [
            'nonce' => $nonce,
            'expiresAt' => $expiresAt,
            'expiresIn' => self::NONCE_TTL,
        ];
    }

    /**
     * Read the clearance TTL carried by a nonce, or null when it carries none.
     *
     * The caller MUST have already verified the nonce (see {@see Verifier}); this
     * only decodes the signed claims and does not re-check authenticity or expiry.
     */
    public function clearanceTtl(string $nonce): ?int
    {
        $claims = $this->signer->parse($nonce);
        if ($claims === null || !isset($claims['ctl']) || !\is_int($claims['ctl'])) {
            return null;
        }

        return $claims['ctl'];
    }
}
