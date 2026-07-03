<?php

namespace Utopia\WAF\Challenge;

/**
 * The interactive ("slider") challenge — a first-party humanity gate whose pass
 * is a *server verdict*, not a client claim.
 *
 * The forgeability of a client-asserted `interacted: true` is a secret-location
 * problem, not a widget problem. Here the secret lives on the server: it chooses
 * a gap offset X, renders a puzzle image with the gap at X (rendering lives at the
 * edge — this class is pure math), and bakes only a keyed one-way hash of X's
 * bucket into the signed token, never X itself. A client can learn X only by
 * looking at the rendered pixels, and cannot verify a guess offline because the
 * signing secret is server-only — it must submit each guess to the server, where
 * guesses are rate-limited and cost the carried proof of work.
 *
 * Verification is a stateless HMAC check, exactly like the PoW path
 * ({@see Verifier}): no per-challenge state is stored. The token also carries a
 * PoW cost ({@see Pow}) so a blind guess against the (necessarily coarse) bucket
 * grid is not free — each attempt costs CPU and a miss re-challenges with a fresh
 * image.
 *
 * Context binding (project + audience + IP prefix) is identical to the PoW nonce,
 * so the interactive token inherits IP-pinning and key rotation for free.
 */
final class Interactive
{
    public const TYPE = 'ichal';

    /** Horizontal range, in px, the gap can occupy. */
    public const GAP_MIN = 0;
    public const GAP_MAX = 260;

    /**
     * Quantization of the drop position, in px. A human's imprecise drag (and a
     * slider that snaps to this grid) still lands in the gap's bucket; it is also
     * the verify tolerance. Coarser = more human-forgiving but a higher blind-guess
     * rate, which the carried PoW + rate-limiting offset.
     */
    public const BUCKET_SIZE = 6;

    public const NONCE_TTL = 120;

    /** Clock-skew tolerance, in seconds, applied to token timestamps. */
    public const LEEWAY = 5;

    /** Max PoW solution length accepted, guarding the verify hash. */
    public const SOLUTION_MAX_LENGTH = 64;

    public function __construct(private readonly Signer $signer)
    {
    }

    /**
     * Mint an interactive challenge whose gap sits at `$gap` px. `$gap` is used
     * only to render the image and to derive the answer hash — it never leaves the
     * server in plaintext. The token also carries a proof of work (`$difficulty`,
     * optional `$memory`) the client must solve, scaled exactly like {@see Issuer}.
     *
     * @return array{token: string, gap: int, difficulty: int, memory: int, expiresAt: int, expiresIn: int}
     */
    public function issue(
        Context $context,
        int $gap,
        int $difficulty = Issuer::DIFFICULTY_DEFAULT,
        int $memory = 0,
        ?int $clearanceTtl = null,
    ): array {
        // Snap the gap to the bucket grid so a client that also snaps aligns
        // exactly, and clamp into range.
        $gap = \max(self::GAP_MIN, \min(self::GAP_MAX, $gap));
        $gap = $this->bucket($gap) * self::BUCKET_SIZE;

        $memory = $memory > 0 ? \max(Issuer::MEMORY_MIN, \min(Issuer::MEMORY_MAX, $memory)) : 0;
        $difficulty = $memory > 0
            ? Issuer::toMemoryDifficulty($difficulty)
            : \max(Issuer::DIFFICULTY_MIN, \min(Issuer::DIFFICULTY_MAX, $difficulty));

        $issuedAt = \time();
        $expiresAt = $issuedAt + self::NONCE_TTL;
        $rnd = \bin2hex(\random_bytes(8));

        $claims = [
            'typ' => self::TYPE,
            'ver' => 1,
            'pid' => $context->projectId,
            'aud' => $context->audience,
            'iph' => $this->signer->fingerprintIp($context->ip),
            'dif' => $difficulty,
            'iat' => $issuedAt,
            'exp' => $expiresAt,
            'rnd' => $rnd,
            // The answer, one-way: HMAC(secret, rnd . bucket(gap)). Public in the
            // token, but unrecomputable without the secret — this is what makes the
            // pass unforgeable.
            'sol' => $this->signer->mac($rnd . '.' . $this->bucket($gap)),
        ];

        if ($memory > 0) {
            $claims['mem'] = $memory;
        }

        if ($clearanceTtl !== null) {
            $claims['ctl'] = $clearanceTtl;
        }

        $token = $this->signer->sign($claims);

        return [
            'token' => $token,
            'gap' => $gap,
            'difficulty' => $difficulty,
            'memory' => $memory,
            'expiresAt' => $expiresAt,
            'expiresIn' => self::NONCE_TTL,
        ];
    }

    /**
     * Accept the challenge only when the token is authentic, unexpired, bound to
     * the same context, its carried PoW is solved, AND the submitted offset falls
     * in the secret gap's bucket — checked against the token's HMAC so the server
     * never re-learns the gap. All stateless.
     */
    public function verify(string $token, int $offset, string $powSolution, Context $context): bool
    {
        if ($powSolution === '' || \strlen($powSolution) > self::SOLUTION_MAX_LENGTH) {
            return false;
        }

        $claims = $this->signer->parse($token);
        if ($claims === null || ($claims['typ'] ?? null) !== self::TYPE) {
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
        if (!\hash_equals($this->signer->fingerprintIp($context->ip, $kid), (string) ($claims['iph'] ?? ''))) {
            return false;
        }

        // The carried proof of work must be solved first: it is what makes each
        // guess against the coarse bucket grid cost CPU.
        $difficulty = (int) ($claims['dif'] ?? 0);
        if ($difficulty <= 0) {
            return false;
        }
        $memory = (int) ($claims['mem'] ?? 0);
        if ($memory > 0) {
            $memory = \min($memory, Issuer::MEMORY_MAX);
        }
        if (!Pow::meets($token . '.' . $powSolution, $difficulty, $memory)) {
            return false;
        }

        // The submitted offset must reproduce the answer hash. hash_equals against
        // the token's `sol`; the gap itself is never recovered server-side.
        $expected = (string) ($claims['sol'] ?? '');
        if ($expected === '') {
            return false;
        }
        $actual = $this->signer->mac((string) ($claims['rnd'] ?? '') . '.' . $this->bucket($offset), $kid);

        return \hash_equals($expected, $actual);
    }

    /**
     * Read the clearance TTL carried by a token, or null when it carries none.
     * The caller MUST have already verified the token.
     */
    public function clearanceTtl(string $token): ?int
    {
        $claims = $this->signer->parse($token);
        if ($claims === null || !isset($claims['ctl']) || !\is_int($claims['ctl'])) {
            return null;
        }

        return $claims['ctl'];
    }

    /**
     * Quantize a horizontal offset to the bucket grid (the human-drag tolerance).
     */
    public function bucket(int $offset): int
    {
        return \intdiv(\max(0, $offset), self::BUCKET_SIZE);
    }
}
