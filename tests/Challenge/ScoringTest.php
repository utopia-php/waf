<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Scoring\HeuristicEngine;
use Utopia\WAF\Challenge\Scoring\RiskTier;
use Utopia\WAF\Challenge\Scoring\Score;
use Utopia\WAF\Challenge\Scoring\Signal;
use Utopia\WAF\Challenge\Scoring\SignalRecord;
use Utopia\WAF\Challenge\Scoring\Signals;

class ScoringTest extends TestCase
{
    public function testSignalsBagIsImmutableAndNormalizes(): void
    {
        $base = new Signals();
        $withOne = $base->with(Signal::IP_REPUTATION, 0.5);

        $this->assertFalse($base->has(Signal::IP_REPUTATION)); // original untouched
        $this->assertTrue($withOne->has(Signal::IP_REPUTATION));
        $this->assertSame(0.5, $withOne->float(Signal::IP_REPUTATION));

        // bool -> 1.0/0.0, clamping, defaults
        $this->assertSame(1.0, $withOne->with(Signal::TLS_MISMATCH, true)->float(Signal::TLS_MISMATCH));
        $this->assertSame(0.0, $withOne->with(Signal::TLS_MISMATCH, false)->float(Signal::TLS_MISMATCH));
        $this->assertSame(1.0, $withOne->with(Signal::HEADLESS, 5)->float(Signal::HEADLESS)); // clamped
        $this->assertSame(0.0, $base->float(Signal::HEADLESS)); // absent -> default
        $this->assertTrue($withOne->with(Signal::INTERACTION_PASSED, true)->bool(Signal::INTERACTION_PASSED));
    }

    public function testRiskTierFromScoreBoundaries(): void
    {
        $this->assertSame(RiskTier::ALLOW, RiskTier::fromScore(0.0));
        $this->assertSame(RiskTier::ALLOW, RiskTier::fromScore(0.24));
        $this->assertSame(RiskTier::CHALLENGE, RiskTier::fromScore(0.25));
        $this->assertSame(RiskTier::CHALLENGE, RiskTier::fromScore(0.54));
        $this->assertSame(RiskTier::INTERACTIVE, RiskTier::fromScore(0.55));
        $this->assertSame(RiskTier::INTERACTIVE, RiskTier::fromScore(0.79));
        $this->assertSame(RiskTier::DENY, RiskTier::fromScore(0.80));
        $this->assertSame(RiskTier::DENY, RiskTier::fromScore(1.5)); // clamped
    }

    public function testRiskTierSurfaceClamp(): void
    {
        // cloud API (no browser): interactive falls back to proof-of-work
        $this->assertSame(RiskTier::CHALLENGE, RiskTier::INTERACTIVE->clampTo(false));
        // edge (browser): interactive stays
        $this->assertSame(RiskTier::INTERACTIVE, RiskTier::INTERACTIVE->clampTo(true));
        // every other tier is surface-agnostic
        $this->assertSame(RiskTier::DENY, RiskTier::DENY->clampTo(false));
        $this->assertSame(RiskTier::CHALLENGE, RiskTier::CHALLENGE->clampTo(false));
        $this->assertSame(RiskTier::ALLOW, RiskTier::ALLOW->clampTo(false));
    }

    public function testHeuristicEmptySignalsAllow(): void
    {
        $score = (new HeuristicEngine())->score(new Signals());
        $this->assertSame(0.0, $score->value);
        $this->assertSame(RiskTier::ALLOW, $score->tier);
        $this->assertSame([], $score->contributions);
    }

    public function testHeuristicEscalatesWithSignalWeight(): void
    {
        $engine = new HeuristicEngine();

        // single low-weight-ish signal stays ALLOW (conservative, fixed denominator)
        $this->assertSame(RiskTier::ALLOW, $engine->score(
            (new Signals())->with(Signal::IP_REPUTATION, 1.0)
        )->tier);

        // IP reputation + TLS mismatch crosses into the PoW gate
        $this->assertSame(RiskTier::CHALLENGE, $engine->score(
            (new Signals())
                ->with(Signal::IP_REPUTATION, 1.0)
                ->with(Signal::TLS_MISMATCH, true)
        )->tier);

        // all server signals maxed -> interactive
        $this->assertSame(RiskTier::INTERACTIVE, $engine->score(
            (new Signals())
                ->with(Signal::IP_REPUTATION, 1.0)
                ->with(Signal::ASN_REPUTATION, 1.0)
                ->with(Signal::TLS_MISMATCH, true)
                ->with(Signal::MISSING_HEADERS, 1.0)
        )->tier);

        // everything maxed -> deny, score 1.0, contributions recorded
        $all = $engine->score(
            (new Signals())
                ->with(Signal::IP_REPUTATION, 1.0)
                ->with(Signal::ASN_REPUTATION, 1.0)
                ->with(Signal::TLS_MISMATCH, true)
                ->with(Signal::MISSING_HEADERS, 1.0)
                ->with(Signal::HEADLESS, 1.0)
                ->with(Signal::AUTOMATION_FLAGS, 1.0)
                ->with(Signal::BEHAVIORAL_RISK, 1.0)
        );
        $this->assertSame(1.0, $all->value);
        $this->assertSame(RiskTier::DENY, $all->tier);
        $this->assertCount(7, $all->contributions);
        $this->assertEqualsWithDelta(1.0, array_sum($all->contributions), 1e-9);
    }

    public function testInteractionPassHardCapsToAllow(): void
    {
        // even a fully bot-looking request is cleared once it passes the interaction challenge
        $score = (new HeuristicEngine())->score(
            (new Signals())
                ->with(Signal::IP_REPUTATION, 1.0)
                ->with(Signal::TLS_MISMATCH, true)
                ->with(Signal::HEADLESS, 1.0)
                ->with(Signal::INTERACTION_PASSED, true)
        );
        $this->assertLessThanOrEqual(HeuristicEngine::INTERACTION_PASS_CEILING, $score->value);
        $this->assertSame(RiskTier::ALLOW, $score->tier);
    }

    public function testCustomThresholdsAndWeights(): void
    {
        // a stricter config escalates the same signal further
        $engine = new HeuristicEngine(
            weights: [Signal::HEADLESS => 1.0],
            thresholds: [
                RiskTier::CHALLENGE->value => 0.1,
                RiskTier::INTERACTIVE->value => 0.5,
                RiskTier::DENY->value => 0.9,
            ],
        );
        $this->assertSame(RiskTier::DENY, $engine->score(
            (new Signals())->with(Signal::HEADLESS, 1.0)
        )->tier);
    }

    public function testSignalRecordFlattens(): void
    {
        $signals = (new Signals())->with(Signal::HEADLESS, 0.8);
        $score = new Score(0.8, RiskTier::INTERACTIVE, [Signal::HEADLESS => 0.8]);
        $record = new SignalRecord(
            projectId: 'proj',
            audience: 'wafedge.test',
            ipPrefix: '203.0.113.0',
            signals: $signals,
            score: $score,
            decision: RiskTier::CHALLENGE, // clamped for a non-interactive surface
            enforced: false,
            issuedAt: 1000,
            requestId: 'req-1',
        );

        $row = $record->toArray();
        $this->assertSame('waf.score', $row['type']);
        $this->assertSame('proj', $row['projectId']);
        $this->assertSame(0.8, $row['score']);
        $this->assertSame('interactive', $row['tier']);
        $this->assertSame('challenge', $row['decision']);
        $this->assertFalse($row['enforced']);
        $this->assertSame(['headless' => 0.8], $row['signals']);
    }

    public function testCertainAttackFloorsToDeny(): void
    {
        // a clear attack blocks even with no other signals
        $score = (new HeuristicEngine())->score((new Signals())->with(Signal::ATTACK_SCORE, 1.0));
        $this->assertSame(RiskTier::DENY, $score->tier);
    }

    public function testModerateAttackFloorsToChallenge(): void
    {
        $score = (new HeuristicEngine())->score((new Signals())->with(Signal::ATTACK_SCORE, 0.5));
        $this->assertSame(RiskTier::CHALLENGE, $score->tier);
    }

    public function testLowAttackScoreDoesNotFloor(): void
    {
        $score = (new HeuristicEngine())->score((new Signals())->with(Signal::ATTACK_SCORE, 0.2));
        $this->assertSame(RiskTier::ALLOW, $score->tier);
    }

    public function testAttackFloorOverridesInteractionCap(): void
    {
        // you never excuse an injection because a challenge was solved
        $score = (new HeuristicEngine())->score(
            (new Signals())
                ->with(Signal::ATTACK_SCORE, 1.0)
                ->with(Signal::INTERACTION_PASSED, true)
        );
        $this->assertSame(RiskTier::DENY, $score->tier);
    }

    public function testAttackScoreIsNotDilutedByWeightedSum(): void
    {
        // ATTACK_SCORE is a floor, not a weighted contribution — it never appears
        // in contributions and never shifts the denominator of the other signals
        $score = (new HeuristicEngine())->score(
            (new Signals())
                ->with(Signal::IP_REPUTATION, 1.0)
                ->with(Signal::ATTACK_SCORE, 1.0)
        );
        $this->assertArrayNotHasKey(Signal::ATTACK_SCORE, $score->contributions);
        $this->assertArrayHasKey(Signal::IP_REPUTATION, $score->contributions);
    }
}
