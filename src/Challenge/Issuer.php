<?php

namespace Utopia\WAF\Challenge;

/**
 * Issues WAF challenges.
 *
 * The client must find a `solution` such that the proof-of-work digest of
 * `nonce . '.' . solution` has at least `difficulty` leading zero bits. The
 * digest is plain SHA-256 by default, or a memory-hard variant when the challenge
 * is minted with a `memory` cost (see {@see Pow}). The nonce is a signed,
 * short-lived, context-bound token — issuance is stateless and verification (see
 * Verifier) recomputes a single digest.
 */
final class Issuer
{
    public const DIFFICULTY_MIN = 16;
    public const DIFFICULTY_DEFAULT = 20;
    public const DIFFICULTY_MAX = 24;

    /**
     * Memory-hard mode. `memory` is the scratchpad size in 32-byte blocks; each
     * solution attempt fills and randomly reads it (see {@see Pow::romix()}).
     * Because a memory-hard attempt costs ~2·memory hashes, the difficulty band
     * is far lower than the CPU-only one — few attempts, each expensive — so the
     * browser stays responsive while a farm loses its parallelism advantage.
     */
    public const MEMORY_MIN = 1;
    public const MEMORY_DEFAULT = 512; // 512 blocks × 32 B = 16 KB scratchpad
    public const MEMORY_MAX = 4096;    // 128 KB

    public const MEMORY_DIFFICULTY_MIN = 4;
    public const MEMORY_DIFFICULTY_DEFAULT = 8;
    public const MEMORY_DIFFICULTY_MAX = 12;

    public const NONCE_TTL = 120;

    public const ALGORITHM = Pow::ALGORITHM_SHA256;

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
     * `$clearanceTtl`, when given, is carried inside the signed nonce (claim
     * `ctl`) so the solve endpoint — which only receives the nonce, never the
     * matched rule — can mint the clearance with the rule's configured lifetime.
     * It is authenticated by the nonce signature; read it back with
     * {@see self::clearanceTtl()} after verification.
     *
     * `$memory`, when greater than zero, switches the challenge to the memory-hard
     * proof of work and is clamped to `[MEMORY_MIN, MEMORY_MAX]`; the difficulty is
     * then interpreted (and clamped) in the lower memory-mode band. It is carried
     * in the signed nonce (claim `mem`) so the Verifier recomputes the same digest.
     *
     * @return array{nonce: string, difficulty: int, algorithm: string, memory: int, expiresAt: int, expiresIn: int}
     */
    public function issue(Context $context, int $difficulty = self::DIFFICULTY_DEFAULT, ?int $clearanceTtl = null, int $memory = 0): array
    {
        $memory = $memory > 0 ? \max(self::MEMORY_MIN, \min(self::MEMORY_MAX, $memory)) : 0;

        $difficulty = $memory > 0
            ? self::toMemoryDifficulty($difficulty)
            : \max(self::DIFFICULTY_MIN, \min(self::DIFFICULTY_MAX, $difficulty));

        $issuedAt = \time();
        $expiresAt = $issuedAt + self::NONCE_TTL;

        $claims = [
            'typ' => 'challenge',
            'ver' => 1,
            'pid' => $context->projectId,
            'aud' => $context->audience,
            'iph' => $this->signer->fingerprintIp($context->ip),
            'dif' => $difficulty,
            'iat' => $issuedAt,
            'exp' => $expiresAt,
            'rnd' => \bin2hex(\random_bytes(16)),
        ];

        if ($memory > 0) {
            $claims['mem'] = $memory;
        }

        if ($clearanceTtl !== null) {
            $claims['ctl'] = $clearanceTtl;
        }

        $nonce = $this->signer->sign($claims);

        return [
            'nonce' => $nonce,
            'difficulty' => $difficulty,
            'algorithm' => Pow::algorithm($memory),
            'memory' => $memory,
            'expiresAt' => $expiresAt,
            'expiresIn' => self::NONCE_TTL,
        ];
    }

    /**
     * Map a CPU-band difficulty onto the memory-hard band, preserving scale.
     *
     * Callers store and pass difficulty in the CPU band [DIFFICULTY_MIN,
     * DIFFICULTY_MAX] — the rule config validator and the adaptive bump both live
     * there. A memory-hard attempt is far more expensive than a bare SHA-256 one,
     * so the same knob has to land in the much lower memory band. Translating
     * proportionally (16→4, 20→8, 24→12) keeps the rule's difficulty setting and
     * the adaptive ladder meaningful; a naive re-clamp would collapse every
     * CPU-band input to the memory-band maximum, i.e. the slowest possible solve.
     *
     * Public so the interactive challenge ({@see Interactive}), which carries its
     * own PoW, scales difficulty identically.
     */
    public static function toMemoryDifficulty(int $difficulty): int
    {
        $cpu = \max(self::DIFFICULTY_MIN, \min(self::DIFFICULTY_MAX, $difficulty));

        $cpuSpan = self::DIFFICULTY_MAX - self::DIFFICULTY_MIN;
        $memorySpan = self::MEMORY_DIFFICULTY_MAX - self::MEMORY_DIFFICULTY_MIN;
        $fraction = ($cpu - self::DIFFICULTY_MIN) / $cpuSpan;

        return self::MEMORY_DIFFICULTY_MIN + (int) \round($fraction * $memorySpan);
    }

    /**
     * Read the clearance TTL carried by a nonce, or null when it carries none.
     *
     * The caller MUST have already verified the nonce (see Verifier); this only
     * decodes the signed claims and does not re-check authenticity or expiry.
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
