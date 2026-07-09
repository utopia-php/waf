<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Context;
use Utopia\WAF\Challenge\Scoring\Engine;
use Utopia\WAF\Challenge\Scoring\HeuristicEngine;
use Utopia\WAF\Challenge\Scoring\RiskTier;
use Utopia\WAF\Challenge\Scoring\Score;
use Utopia\WAF\Challenge\Scoring\Signals;
use Utopia\WAF\Challenge\SilentChallenge;
use Utopia\WAF\Challenge\Signer;

/**
 * The silent-tier orchestrator: issue a nonce, then on the returned attestation
 * confirm the nonce's integrity and hand the attested signals to the scoring
 * engine. Integrity is a hard gate — a forged/expired/mis-bound nonce yields null
 * and the engine is never consulted; a live nonce yields the engine's Score.
 */
class SilentChallengeTest extends TestCase
{
    private const SECRET = 'unit-test-secret-please-rotate';

    private function context(string $ip = '203.0.113.9'): Context
    {
        return new Context('proj-123', 'api', $ip);
    }

    private function silent(Engine $engine): SilentChallenge
    {
        return SilentChallenge::create(new Signer(self::SECRET), $engine);
    }

    public function testIssueMintsANonce(): void
    {
        $challenge = $this->silent(new SpyEngine())->issue($this->context());

        $this->assertArrayHasKey('nonce', $challenge);
        $this->assertNotSame('', $challenge['nonce']);
    }

    public function testVerifyReturnsEngineScoreForAuthenticNonce(): void
    {
        $verdict = new Score(0.42, RiskTier::INTERACTIVE, ['headless' => 0.42]);
        $engine = new SpyEngine($verdict);
        $silent = $this->silent($engine);

        $nonce = $silent->issue($this->context())['nonce'];
        $signals = new Signals(['headless' => 1.0]);

        $score = $silent->verify($nonce, $signals, $this->context());

        $this->assertSame($verdict, $score, 'the engine verdict is returned verbatim');
        $this->assertSame(1, $engine->calls, 'engine is consulted exactly once for a live nonce');
        $this->assertSame($signals, $engine->lastSignals, 'the attested signals are what gets scored');
    }

    public function testVerifyReturnsNullAndSkipsScoringForForgedNonce(): void
    {
        $engine = new SpyEngine();
        $silent = $this->silent($engine);

        // A nonce signed by another secret fails integrity.
        $forged = SilentChallenge::create(new Signer('attacker-secret'), new SpyEngine())
            ->issue($this->context())['nonce'];

        $this->assertNull($silent->verify($forged, new Signals(['headless' => 0.0]), $this->context()));
        $this->assertSame(0, $engine->calls, 'a forged nonce must not reach the engine');

        // Garbage blobs too.
        $this->assertNull($silent->verify('not-a-token', new Signals(), $this->context()));
        $this->assertSame(0, $engine->calls);
    }

    public function testVerifyReturnsNullForWrongContext(): void
    {
        $engine = new SpyEngine();
        $silent = $this->silent($engine);

        $nonce = $silent->issue($this->context('203.0.113.9'))['nonce'];

        // Different /24 network -> integrity fails, engine untouched.
        $this->assertNull($silent->verify($nonce, new Signals(), $this->context('198.51.100.9')));
        $this->assertSame(0, $engine->calls);

        // Same /24 -> integrity passes, engine consulted.
        $this->assertNotNull($silent->verify($nonce, new Signals(), $this->context('203.0.113.200')));
        $this->assertSame(1, $engine->calls);
    }

    public function testVerifyScoresAttestationWithRealEngine(): void
    {
        $silent = $this->silent(new HeuristicEngine());

        $nonce = $silent->issue($this->context())['nonce'];

        // A benign (empty) attestation scores as ALLOW through the real engine.
        $benign = $silent->verify($nonce, new Signals(), $this->context());
        $this->assertInstanceOf(Score::class, $benign);
        $this->assertSame(RiskTier::ALLOW, $benign->tier);
        $this->assertSame(0.0, $benign->value);
    }

    public function testClearanceTtlRoundTrip(): void
    {
        $silent = $this->silent(new SpyEngine());

        $plain = $silent->issue($this->context());
        $this->assertNull($silent->clearanceTtl($plain['nonce']));

        $withTtl = $silent->issue($this->context(), 1800);
        $this->assertSame(1800, $silent->clearanceTtl($withTtl['nonce']));
    }
}

/**
 * A test double for the scoring engine: records how often it was consulted and
 * with what, and returns a preset verdict.
 */
final class SpyEngine implements Engine
{
    public int $calls = 0;

    public ?Signals $lastSignals = null;

    public function __construct(private readonly ?Score $verdict = null)
    {
    }

    public function score(Signals $signals): Score
    {
        $this->calls++;
        $this->lastSignals = $signals;

        return $this->verdict ?? new Score(0.0, RiskTier::ALLOW);
    }
}
