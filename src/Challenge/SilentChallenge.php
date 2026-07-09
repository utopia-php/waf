<?php

namespace Utopia\WAF\Challenge;

use Utopia\WAF\Challenge\Scoring\Engine;
use Utopia\WAF\Challenge\Scoring\Score;
use Utopia\WAF\Challenge\Scoring\Signals;

/**
 * The silent (invisible) challenge — an attestation check, not a puzzle.
 *
 * Where the interactive gate asks a human to *act*, the silent gate asks the
 * client to *reveal itself*. The server issues a fresh, signed, context-bound
 * nonce; an invisible script collects environment/automation signals (webdriver,
 * plugins, WebGL, timing, interaction — the Scoring signal set) and returns them
 * bound to that nonce as an attestation; the server confirms the nonce's integrity
 * and scores the attested signals with the same engine the WAF uses everywhere.
 * Nothing is computed to burn CPU — the cost to a bot is that it must present a
 * *plausible* environment, and a headless/automation environment scores itself
 * into escalation.
 *
 * This class is the silent tier's single entry point in the waf library: it ties
 * the nonce mint ({@see Issuer}), the integrity check ({@see Verifier}), and the
 * scoring {@see Engine} together. It lives beside the engine (not in the captcha
 * leaf) precisely because its verdict *is* a score.
 */
final class SilentChallenge
{
    public function __construct(
        private readonly Issuer $issuer,
        private readonly Verifier $verifier,
        private readonly Engine $engine,
    ) {
    }

    /**
     * Convenience constructor from a signer + scoring engine.
     */
    public static function create(Signer $signer, Engine $engine): self
    {
        return new self(new Issuer($signer), new Verifier($signer), $engine);
    }

    /**
     * Issue a silent-challenge nonce the client must return with its attestation.
     *
     * @return array{nonce: string, expiresAt: int, expiresIn: int}
     */
    public function issue(Context $context, ?int $clearanceTtl = null): array
    {
        return $this->issuer->issue($context, $clearanceTtl);
    }

    /**
     * Verify a returned attestation and score it.
     *
     * The nonce must be authentic, unexpired, and context-bound (anti-replay); the
     * attested `$signals` are then scored by the engine. Returns the resulting
     * {@see Score} (risk value + tier) so the caller can act on it — allow (mint
     * clearance), escalate to the interactive slider, or deny. Returns null only
     * when the nonce itself fails integrity (forged, expired, or wrong context),
     * which the caller should treat as a hard reject rather than a low score.
     */
    public function verify(string $nonce, Signals $signals, Context $context): ?Score
    {
        if (!$this->verifier->verify($nonce, $context)) {
            return null;
        }

        return $this->engine->score($signals);
    }

    /**
     * Read the clearance TTL carried by a verified nonce, or null when it carries
     * none. The caller MUST have already verified the nonce.
     */
    public function clearanceTtl(string $nonce): ?int
    {
        return $this->issuer->clearanceTtl($nonce);
    }
}
