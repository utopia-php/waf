<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * Normalizes the raw telemetry blob collected by the browser interstitial into
 * scoring signals. This is the client-side half of bot-detection — the signals
 * a JSON API can never see, because they need a real page to run JavaScript.
 *
 * The interstitial posts a flat associative array; this turns it into the
 * normalized {@see Signal} values the {@see Engine} scores:
 *  - HEADLESS          — automation-driver / headless-browser tells
 *  - AUTOMATION_FLAGS  — framework artefacts (CDP, Selenium, phantom…)
 *  - BEHAVIORAL_RISK   — absence of human input during the interstitial
 *
 * It deliberately does NOT produce {@see Signal::INTERACTION_PASSED}. That signal
 * hard-caps the score, so it must be unforgeable — a client cannot be trusted to
 * assert it. It is established server-side only, by verifying the interactive
 * challenge whose answer the client can prove only by reading the rendered pixels
 * (see {@see \Utopia\WAF\Challenge\Interactive}). The blob's own `interacted`
 * flag still lowers BEHAVIORAL_RISK (real input happened) but grants no humanity
 * pass on its own.
 *
 * Heuristics are intentionally simple and explainable (v1); an ML engine can
 * later consume the same raw blob. Every field is optional and defensively read,
 * because the blob is attacker-controlled — a missing/garbage field must never
 * throw, only lower confidence.
 */
final class ClientSignals
{
    /**
     * @param array<string, mixed> $raw the interstitial telemetry blob
     * @return array<string, mixed> Signal key => normalized value, to fold into a Signals bag
     */
    public static function normalize(array $raw): array
    {
        return [
            Signal::HEADLESS => self::headless($raw),
            Signal::AUTOMATION_FLAGS => self::automation($raw),
            Signal::BEHAVIORAL_RISK => self::behavioral($raw),
        ];
    }

    /**
     * Headless / automation-driver detection. `navigator.webdriver` is near-proof
     * on its own; otherwise combine the soft tells (no plugins, no languages, a
     * software WebGL renderer — all typical of headless Chromium).
     *
     * @param array<string, mixed> $raw
     */
    private static function headless(array $raw): float
    {
        if (self::boolean($raw, 'webdriver')) {
            return 1.0;
        }

        $risk = 0.0;
        if (self::int($raw, 'plugins', -1) === 0) {
            $risk += 0.4; // real desktop browsers ship plugins; headless has none
        }
        if (self::int($raw, 'languages', -1) === 0) {
            $risk += 0.3; // navigator.languages is empty in many headless setups
        }
        $webgl = \strtolower(self::string($raw, 'webglVendor'));
        if ($webgl !== '' && (\str_contains($webgl, 'swiftshader') || \str_contains($webgl, 'llvmpipe'))) {
            $risk += 0.3; // software renderer ⇒ no GPU ⇒ almost certainly headless
        }

        return \min(1.0, $risk);
    }

    /**
     * Automation-framework artefacts the page can observe (CDP/Selenium/phantom
     * globals). The client reports a count; scale it into [0,1].
     *
     * @param array<string, mixed> $raw
     */
    private static function automation(array $raw): float
    {
        $flags = self::int($raw, 'automationFlags', 0);

        return \max(0.0, \min(1.0, $flags / 3.0));
    }

    /**
     * Behavioral risk: absence of human input while the interstitial was shown.
     * A real user moves the mouse / presses keys; a script solving the PoW does
     * neither. No activity ⇒ high risk; activity drives it down.
     *
     * @param array<string, mixed> $raw
     */
    private static function behavioral(array $raw): float
    {
        $events = self::int($raw, 'mouseMoves', 0) + self::int($raw, 'keyPresses', 0);
        if ($events <= 0) {
            return 1.0;
        }

        // saturating: ~a dozen input events reads as clearly human
        return \max(0.0, 1.0 - \min(1.0, $events / 12.0));
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function boolean(array $raw, string $key): bool
    {
        return isset($raw[$key]) && ($raw[$key] === true || $raw[$key] === 1 || $raw[$key] === '1' || $raw[$key] === 'true');
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function int(array $raw, string $key, int $default): int
    {
        return isset($raw[$key]) && \is_numeric($raw[$key]) ? (int) $raw[$key] : $default;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function string(array $raw, string $key): string
    {
        return isset($raw[$key]) && \is_string($raw[$key]) ? $raw[$key] : '';
    }
}
