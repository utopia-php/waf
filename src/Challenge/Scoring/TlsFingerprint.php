<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * Turns a TLS fingerprint (JA4) + User-Agent into the {@see Signal::TLS_MISMATCH}
 * verdict — the highest-weighted server-side bot signal.
 *
 * The fingerprint is captured at TLS termination (a gateway like Fastly, or the
 * local waf-ja4-proxy). Because it reflects the client's TLS *stack*, it exposes
 * curl/python/Go/headless tools even when they forge browser-looking headers —
 * that is its whole value over HTTP-layer signals.
 *
 * Two detections:
 *  - a known-automation blocklist (library/CLI JA4s) → mismatch regardless of UA;
 *  - a UA cross-check: a mainstream-browser User-Agent whose JA4 is not a known
 *    browser fingerprint is lying about what it is → mismatch.
 *
 * Both lists are injectable. The defaults are a small seed captured locally; in
 * production this is a maintained, measured dataset (the signal is a living thing).
 */
final class TlsFingerprint
{
    /**
     * Seed JA4s of common non-browser clients (captured via waf-ja4-proxy).
     *
     * @var list<string>
     */
    public const KNOWN_AUTOMATION = [
        't13d311200_e8f1e7e78f70_b26ce05bbdd6', // curl (OpenSSL)
        't13d311100_e8f1e7e78f70_d41ae481755e', // python (urllib/OpenSSL)
        't13d751100_479067518aa3_fb8d5ffd48c1', // wget
        't13d591000_a33745022dd6_1f22a2ca17c4', // node.js
    ];

    /**
     * Reference JA4s of mainstream browsers, for the UA cross-check.
     *
     * @var list<string>
     */
    public const KNOWN_BROWSERS = [
        't13d1516h2_8daaf6152771_b186095e22b6', // Chrome (BoringSSL, ALPN h2)
        't13d1715h2_5b57614c22b0_93c746dc12af', // Firefox (NSS, ALPN h2)
    ];

    /**
     * @var array<string, true>
     */
    private array $automation;

    /**
     * @var array<string, true>
     */
    private array $browsers;

    /**
     * @param list<string> $automation known automation/library JA4s
     * @param list<string> $browsers   known mainstream-browser JA4s
     */
    public function __construct(array $automation = self::KNOWN_AUTOMATION, array $browsers = self::KNOWN_BROWSERS)
    {
        $this->automation = \array_fill_keys($automation, true);
        $this->browsers = \array_fill_keys($browsers, true);
    }

    /**
     * Does the fingerprint contradict a real browser? Empty fingerprint (none
     * captured) is not a mismatch — it simply yields no signal.
     */
    public function mismatches(string $fingerprint, string $userAgent): bool
    {
        if ($fingerprint === '') {
            return false;
        }

        if (isset($this->automation[$fingerprint])) {
            return true;
        }

        if ($this->uaClaimsBrowser($userAgent) && !isset($this->browsers[$fingerprint])) {
            return true;
        }

        return false;
    }

    /**
     * Whether the User-Agent claims to be a mainstream browser (and not an
     * obvious bot/library UA).
     */
    private function uaClaimsBrowser(string $userAgent): bool
    {
        $ua = \strtolower($userAgent);

        foreach (['bot', 'crawl', 'spider', 'curl', 'wget', 'python', 'java', 'go-http', 'okhttp', 'axios', 'node'] as $needle) {
            if (\str_contains($ua, $needle)) {
                return false;
            }
        }

        foreach (['chrome', 'firefox', 'safari', 'edg/', 'edge', 'opera', 'gecko'] as $needle) {
            if (\str_contains($ua, $needle)) {
                return true;
            }
        }

        return false;
    }
}
