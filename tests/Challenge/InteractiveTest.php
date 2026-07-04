<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Context;
use Utopia\WAF\Challenge\Interactive;
use Utopia\WAF\Challenge\Issuer;
use Utopia\WAF\Challenge\Pow;
use Utopia\WAF\Challenge\Signer;

class InteractiveTest extends TestCase
{
    private const SECRET = 'interactive-test-secret-please-rotate';

    private function context(string $ip = '203.0.113.9'): Context
    {
        return new Context('proj-123', 'mysite.example', $ip);
    }

    /**
     * Brute-force the carried PoW for an interactive token at a given offset.
     *
     * The offset is part of the PoW preimage (matching Interactive::verify), so a
     * solution is bound to the exact offset it was solved for.
     */
    private function solvePow(string $token, int $offset, int $difficulty, int $memory = 0): string
    {
        for ($i = 0; $i < 5_000_000; $i++) {
            if (Pow::meets($token . '.' . $offset . '.' . $i, $difficulty, $memory)) {
                return (string) $i;
            }
        }

        $this->fail('Could not solve the carried PoW');
    }

    public function testRoundTripAcceptsCorrectOffset(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $gap = 120;
        $challenge = $interactive->issue($this->context(), $gap, Issuer::DIFFICULTY_MIN);
        $pow = $this->solvePow($challenge['token'], $challenge['gap'], $challenge['difficulty']);

        // The client reads the gap from the rendered image and drops the piece
        // there (the returned `gap` is the snapped truth the renderer would draw).
        $this->assertTrue($interactive->verify($challenge['token'], $challenge['gap'], $pow, $this->context()));
    }

    public function testWrongOffsetIsRejected(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $challenge = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);

        // A different bucket (well outside the tolerance) must fail — and with the
        // PoW solved for *that* offset, so the rejection is the bucket check, not a
        // failed proof.
        $this->assertFalse($interactive->verify(
            $challenge['token'],
            60,
            $this->solvePow($challenge['token'], 60, $challenge['difficulty']),
            $this->context(),
        ));
        $this->assertFalse($interactive->verify(
            $challenge['token'],
            200,
            $this->solvePow($challenge['token'], 200, $challenge['difficulty']),
            $this->context(),
        ));
    }

    public function testHumanDragToleranceWithinBucket(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        // Gap snapped to a bucket boundary; an imprecise drop in the same bucket
        // still verifies.
        $challenge = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);
        $offset = $challenge['gap'] + Interactive::BUCKET_SIZE - 1;
        $pow = $this->solvePow($challenge['token'], $offset, $challenge['difficulty']);

        $this->assertSame(0, $challenge['gap'] % Interactive::BUCKET_SIZE, 'gap is snapped to the grid');
        $this->assertTrue(
            $interactive->verify($challenge['token'], $offset, $pow, $this->context())
        );
    }

    public function testTokenNeverCarriesTheGapInPlaintext(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $gap = 120;
        $challenge = $interactive->issue($this->context(), $gap, Issuer::DIFFICULTY_MIN);

        // Decode the (public) claims and confirm the gap is not present — only its
        // one-way HMAC is. This is the whole anti-forgery property.
        $payload = \explode('.', $challenge['token'])[0];
        $claims = \json_decode(\base64_decode(\strtr($payload, '-_', '+/')), true);

        $this->assertArrayNotHasKey('gap', $claims);
        $this->assertArrayNotHasKey('x', $claims);
        $this->assertStringNotContainsString((string) $gap, \json_encode(\array_diff_key($claims, ['iat' => 0, 'exp' => 0])));
        $this->assertSame(32, \strlen((string) $claims['sol']), 'sol is a fixed-length MAC, not the answer');
    }

    public function testForgedTokenFromAnotherSecretIsRejected(): void
    {
        $server = new Interactive(new Signer(self::SECRET));
        $attacker = new Interactive(new Signer('attacker-secret'));

        // The attacker mints a token with a gap they know and computes a matching
        // offset — but signs with their own secret, so the server rejects it.
        $forged = $attacker->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);
        $pow = $this->solvePow($forged['token'], $forged['gap'], $forged['difficulty']);

        $this->assertFalse($server->verify($forged['token'], $forged['gap'], $pow, $this->context()));
    }

    public function testWrongPowIsRejected(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $challenge = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_DEFAULT);

        // Correct offset but the PoW is not solved: the guess must still cost work.
        $this->assertFalse($interactive->verify($challenge['token'], $challenge['gap'], '0', $this->context()));
        $this->assertFalse($interactive->verify($challenge['token'], $challenge['gap'], '', $this->context()));
    }

    public function testContextBinding(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $challenge = $interactive->issue($this->context('203.0.113.9'), 120, Issuer::DIFFICULTY_MIN);
        $gap = $challenge['gap'];
        $pow = $this->solvePow($challenge['token'], $gap, $challenge['difficulty']);

        // Same /24 prefix passes; different project, audience, or IP prefix fails.
        $this->assertTrue($interactive->verify($challenge['token'], $gap, $pow, $this->context('203.0.113.200')));
        $this->assertFalse($interactive->verify($challenge['token'], $gap, $pow, new Context('other', 'mysite.example', '203.0.113.9')));
        $this->assertFalse($interactive->verify($challenge['token'], $gap, $pow, new Context('proj-123', 'other.example', '203.0.113.9')));
        $this->assertFalse($interactive->verify($challenge['token'], $gap, $pow, $this->context('198.51.100.9')));
    }

    public function testTamperedTokenIsRejected(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $challenge = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);
        $pow = $this->solvePow($challenge['token'], $challenge['gap'], $challenge['difficulty']);

        $this->assertFalse($interactive->verify($challenge['token'] . 'x', $challenge['gap'], $pow, $this->context()));
    }

    public function testMemoryHardVariantRoundTrip(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $challenge = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_DEFAULT, 64);
        $this->assertSame(64, $challenge['memory']);
        $this->assertLessThanOrEqual(Issuer::MEMORY_DIFFICULTY_MAX, $challenge['difficulty']);

        $pow = $this->solvePow($challenge['token'], $challenge['gap'], $challenge['difficulty'], $challenge['memory']);
        $this->assertTrue($interactive->verify($challenge['token'], $challenge['gap'], $pow, $this->context()));
    }

    public function testKeyRotationHonorsTokenKid(): void
    {
        // Issue under kid 2, then rotate: kid 3 primary, kid 2 kept as previous.
        $issueSigner = new Signer(self::SECRET, 2);
        $challenge = (new Interactive($issueSigner))->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);
        $pow = $this->solvePow($challenge['token'], $challenge['gap'], $challenge['difficulty']);

        $rotated = new Interactive(new Signer('new-secret', 3, [2 => self::SECRET]));
        $this->assertTrue($rotated->verify($challenge['token'], $challenge['gap'], $pow, $this->context()));
    }

    public function testPowIsBoundToTheSubmittedOffset(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $challenge = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);
        $gap = $challenge['gap'];

        // A PoW solved for a *different* offset does not carry to the correct
        // bucket: the offset is in the preimage, so one solve cannot be sprayed
        // across the grid. (Solve for offset 0, submit at the true gap → rejected
        // on the PoW check even though the bucket is right.)
        $powForZero = $this->solvePow($challenge['token'], 0, $challenge['difficulty']);
        $this->assertFalse($interactive->verify($challenge['token'], $gap, $powForZero, $this->context()));

        // The proof solved for the true offset does verify — sanity that the binding
        // only rejects mismatched offsets, not the honest client.
        $powForGap = $this->solvePow($challenge['token'], $gap, $challenge['difficulty']);
        $this->assertTrue($interactive->verify($challenge['token'], $gap, $powForGap, $this->context()));
    }

    public function testReferenceIdentifiesAuthenticTokensOnly(): void
    {
        $signer = new Signer(self::SECRET);
        $interactive = new Interactive($signer);

        $challenge = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);

        // An authentic token yields its stable nonce; the same token always maps to
        // the same reference (so a counter keyed on it is stable across guesses).
        $ref = $interactive->reference($challenge['token']);
        $this->assertNotNull($ref);
        $this->assertSame($ref, $interactive->reference($challenge['token']));

        // A forged (other-secret) token, a tampered token, and a non-ichal token all
        // yield null — a forged blob cannot seed or exhaust a real token's counter.
        $forged = (new Interactive(new Signer('attacker-secret')))->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);
        $this->assertNull($interactive->reference($forged['token']));
        $this->assertNull($interactive->reference($challenge['token'] . 'x'));
        $this->assertNull($interactive->reference('not-a-token'));
    }

    public function testClearanceTtlRoundTrip(): void
    {
        $interactive = new Interactive(new Signer(self::SECRET));

        $plain = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_MIN);
        $this->assertNull($interactive->clearanceTtl($plain['token']));

        $withTtl = $interactive->issue($this->context(), 120, Issuer::DIFFICULTY_MIN, 0, 1800);
        $this->assertSame(1800, $interactive->clearanceTtl($withTtl['token']));
    }
}
