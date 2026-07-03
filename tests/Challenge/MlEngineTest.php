<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Scoring\MlEngine;
use Utopia\WAF\Challenge\Scoring\RiskTier;
use Utopia\WAF\Challenge\Scoring\Signal;
use Utopia\WAF\Challenge\Scoring\Signals;

class MlEngineTest extends TestCase
{
    private function engine(): MlEngine
    {
        return new MlEngine();
    }

    public function testCleanRequestIsAllowed(): void
    {
        $score = $this->engine()->score(new Signals());

        $this->assertSame(RiskTier::ALLOW, $score->tier);
        $this->assertLessThan(0.25, $score->value); // well below the challenge gate
    }

    public function testBenignSingleSignalStaysAllowed(): void
    {
        // A stripped header or a VPN ASN alone must never manufacture a challenge:
        // the false-positive rate is the metric that hurts most.
        $signals = (new Signals())
            ->with(Signal::MISSING_HEADERS, 0.33)
            ->with(Signal::ASN_REPUTATION, 0.3);

        $this->assertSame(RiskTier::ALLOW, $this->engine()->score($signals)->tier);
    }

    public function testHeadlessBotIsEscalated(): void
    {
        // navigator.webdriver + no organic interaction — the puppeteer/selenium
        // shape. The learned model should push this to the top of the ladder.
        $signals = (new Signals())
            ->with(Signal::HEADLESS, 1.0)
            ->with(Signal::AUTOMATION_FLAGS, 0.66)
            ->with(Signal::BEHAVIORAL_RISK, 1.0);

        $score = $this->engine()->score($signals);

        $this->assertGreaterThanOrEqual(0.80, $score->value);
        $this->assertSame(RiskTier::DENY, $score->tier);
    }

    public function testScriptedClientWithTlsMismatchIsDenied(): void
    {
        // curl / python-requests hitting the interstitial: no JS engine, TLS
        // fingerprint contradicts any browser UA.
        $signals = (new Signals())
            ->with(Signal::TLS_MISMATCH, true)
            ->with(Signal::MISSING_HEADERS, 0.5)
            ->with(Signal::HEADLESS, 1.0)
            ->with(Signal::BEHAVIORAL_RISK, 1.0);

        $this->assertSame(RiskTier::DENY, $this->engine()->score($signals)->tier);
    }

    public function testPassedInteractionCapsTheScore(): void
    {
        // Even a bot-shaped request is capped below the first gate once the client
        // proves humanity by passing the interaction challenge.
        $signals = (new Signals())
            ->with(Signal::HEADLESS, 1.0)
            ->with(Signal::BEHAVIORAL_RISK, 1.0)
            ->with(Signal::AUTOMATION_FLAGS, 1.0)
            ->with(Signal::INTERACTION_PASSED, true);

        $score = $this->engine()->score($signals);

        $this->assertLessThanOrEqual(MlEngine::INTERACTION_PASS_CEILING, $score->value);
        $this->assertSame(RiskTier::ALLOW, $score->tier);
    }

    public function testPassedInteractionDoesNotEraseServerSignals(): void
    {
        // A forged interaction must not neutralize server-observed evidence. With
        // strong reputation + TLS mismatch the learned server-only probability is
        // well above the interaction ceiling, so the score cannot be capped to
        // ALLOW — only the client-behavioral contribution is neutralized.
        $signals = (new Signals())
            ->with(Signal::IP_REPUTATION, 1.0)
            ->with(Signal::ASN_REPUTATION, 1.0)
            ->with(Signal::TLS_MISMATCH, true)
            ->with(Signal::HEADLESS, 1.0)          // client noise — neutralized
            ->with(Signal::AUTOMATION_FLAGS, 1.0)
            ->with(Signal::INTERACTION_PASSED, true);

        $score = $this->engine()->score($signals);

        $this->assertGreaterThan(MlEngine::INTERACTION_PASS_CEILING, $score->value);
        $this->assertNotSame(RiskTier::ALLOW, $score->tier);

        // Score equals the server-only probability (client tells neutralized).
        $serverOnly = $this->engine()->score(
            (new Signals())
                ->with(Signal::IP_REPUTATION, 1.0)
                ->with(Signal::ASN_REPUTATION, 1.0)
                ->with(Signal::TLS_MISMATCH, true)
        );
        $this->assertEqualsWithDelta($serverOnly->value, $score->value, 1e-9);
    }

    public function testAttackScoreFloorsToDeny(): void
    {
        // A high request-inspection score is decisive: it floors the verdict to
        // deny regardless of how benign the behavioural signals look, and it is
        // applied after (so it survives) any interaction cap.
        $signals = (new Signals())
            ->with(Signal::ATTACK_SCORE, 0.9)
            ->with(Signal::INTERACTION_PASSED, true);

        $score = $this->engine()->score($signals);

        $this->assertGreaterThanOrEqual(0.80, $score->value);
        $this->assertSame(RiskTier::DENY, $score->tier);
    }

    public function testModerateAttackScoreFloorsToChallenge(): void
    {
        $signals = (new Signals())->with(Signal::ATTACK_SCORE, 0.45);

        $score = $this->engine()->score($signals);

        $this->assertGreaterThanOrEqual(0.25, $score->value);
        $this->assertSame(RiskTier::CHALLENGE, $score->tier);
    }

    public function testContributionsAreRecordedPerSignal(): void
    {
        $signals = (new Signals())
            ->with(Signal::HEADLESS, 1.0)
            ->with(Signal::ASN_REPUTATION, 0.5);

        $contributions = $this->engine()->score($signals)->contributions;

        $this->assertArrayHasKey(Signal::HEADLESS, $contributions);
        $this->assertArrayHasKey(Signal::ASN_REPUTATION, $contributions);
        // logit-space contribution = coefficient * value
        $this->assertGreaterThan(0.0, $contributions[Signal::HEADLESS]);
    }

    public function testImplementsEngineInterface(): void
    {
        // The whole point of the class: it is a drop-in for the heuristic engine.
        $this->assertInstanceOf(\Utopia\WAF\Challenge\Scoring\Engine::class, $this->engine());
    }
}
