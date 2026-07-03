<?php

namespace Utopia\WAF\Challenge\Scoring;

/**
 * The bot-detection signal schema — the normalized feature keys the scoring
 * engine understands.
 *
 * Signals are split by where they can be collected:
 *  - SERVER signals are available on every request (cloud API and edge).
 *  - CLIENT signals need a browser page to run JavaScript, so they are only
 *    available at the edge interstitial (never on the JSON API).
 *
 * Each value is a normalized bot-risk contribution in [0,1] (higher = more
 * bot-like), except {@see self::INTERACTION_PASSED} which is a boolean humanity
 * assertion the engine treats as an allow-override. Keeping the bag raw and
 * typed (not pre-scored) is deliberate: a future ML engine consumes the exact
 * same features without a schema change.
 */
final class Signal
{
    /* --- Server-side (cloud API + edge) --- */

    /** float [0,1] — IP-level abuse reputation (blocklists, prior offences). */
    public const IP_REPUTATION = 'ipReputation';

    /** float [0,1] — ASN/network-level reputation (hosting/VPN ranges score higher). */
    public const ASN_REPUTATION = 'asnReputation';

    /** bool — the TLS/HTTP fingerprint (JA3/JA4) contradicts the claimed User-Agent. */
    public const TLS_MISMATCH = 'tlsMismatch';

    /** string — the raw TLS fingerprint, carried for logging/analysis (not scored directly). */
    public const TLS_FINGERPRINT = 'tlsFingerprint';

    /** float [0,1] — proportion of expected real-browser request headers that are absent. */
    public const MISSING_HEADERS = 'missingHeaders';

    /* --- Client-side (edge interstitial only) --- */

    /** float [0,1] — headless/automation indicators (navigator.webdriver, missing plugins…). */
    public const HEADLESS = 'headless';

    /** float [0,1] — automation-framework flags (CDP, Selenium/Puppeteer artefacts). */
    public const AUTOMATION_FLAGS = 'automationFlags';

    /** float [0,1] — behavioral-biometrics risk (mouse/keystroke dynamics). */
    public const BEHAVIORAL_RISK = 'behavioralRisk';

    /** bool — the client passed the interaction (first-party captcha) challenge. */
    public const INTERACTION_PASSED = 'interactionPassed';

    /**
     * Signal keys collectible without a browser page — the subset the cloud API
     * surface can populate.
     *
     * @var list<string>
     */
    public const SERVER = [
        self::IP_REPUTATION,
        self::ASN_REPUTATION,
        self::TLS_MISMATCH,
        self::TLS_FINGERPRINT,
        self::MISSING_HEADERS,
    ];

    /**
     * Signal keys that require client JavaScript — edge interstitial only.
     *
     * @var list<string>
     */
    public const CLIENT = [
        self::HEADLESS,
        self::AUTOMATION_FLAGS,
        self::BEHAVIORAL_RISK,
        self::INTERACTION_PASSED,
    ];
}
