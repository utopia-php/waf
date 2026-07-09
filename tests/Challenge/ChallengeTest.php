<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Context;
use Utopia\WAF\Challenge\Issuer;
use Utopia\WAF\Challenge\Signer;
use Utopia\WAF\Challenge\Verifier;

/**
 * Silent-tier nonce tests: the Issuer mints a signed, context-bound, short-lived
 * anti-replay nonce (no proof-of-work), and the Verifier answers only "is this a
 * genuine, live challenge for this client?". Scoring the attested signals is the
 * orchestrator's job ({@see \Utopia\WAF\Challenge\SilentChallenge}, tested in
 * SilentChallengeTest).
 */
class ChallengeTest extends TestCase
{
    private const SECRET = 'unit-test-secret-please-rotate';

    private function context(string $ip = '203.0.113.9'): Context
    {
        return new Context('proj-123', 'api', $ip);
    }

    public function testIssueMintsContextBoundNonce(): void
    {
        $issuer = new Issuer(new Signer(self::SECRET));

        $challenge = $issuer->issue($this->context());

        $this->assertArrayHasKey('nonce', $challenge);
        $this->assertSame(Issuer::NONCE_TTL, $challenge['expiresIn']);
        $this->assertSame($challenge['expiresIn'], $challenge['expiresAt'] - \time());

        // No proof-of-work is advertised any more: the nonce carries no difficulty,
        // memory, or algorithm.
        $claims = \json_decode(\base64_decode(\strtr(\explode('.', $challenge['nonce'])[0], '-_', '+/')), true);
        $this->assertArrayNotHasKey('dif', $claims);
        $this->assertArrayNotHasKey('mem', $claims);
        $this->assertSame('challenge', $claims['typ']);
    }

    public function testVerifyAcceptsAuthenticNonce(): void
    {
        $signer = new Signer(self::SECRET);
        $issuer = new Issuer($signer);
        $verifier = new Verifier($signer);

        $nonce = $issuer->issue($this->context())['nonce'];
        $this->assertTrue($verifier->verify($nonce, $this->context()));
    }

    public function testVerifyRejectsExpiredNonce(): void
    {
        $signer = new Signer(self::SECRET);
        $verifier = new Verifier($signer);

        $nonce = $signer->sign([
            'typ' => 'challenge',
            'pid' => 'proj-123',
            'aud' => 'api',
            'iph' => $signer->fingerprintIp('203.0.113.9'),
            'iat' => \time() - 1000,
            'exp' => \time() - 500,
        ]);

        $this->assertFalse($verifier->verify($nonce, $this->context()));
    }

    public function testVerifyRejectsWrongContext(): void
    {
        $signer = new Signer(self::SECRET);
        $issuer = new Issuer($signer);
        $verifier = new Verifier($signer);

        $nonce = $issuer->issue($this->context('203.0.113.9'))['nonce'];

        $this->assertFalse($verifier->verify($nonce, new Context('other-project', 'api', '203.0.113.9')));
        $this->assertFalse($verifier->verify($nonce, new Context('proj-123', 'mysite.example', '203.0.113.9')));
        // Different /24 network.
        $this->assertFalse($verifier->verify($nonce, new Context('proj-123', 'api', '198.51.100.9')));
        // Same /24 still passes.
        $this->assertTrue($verifier->verify($nonce, new Context('proj-123', 'api', '203.0.113.200')));
    }

    public function testVerifyRejectsForeignSecret(): void
    {
        $issued = (new Issuer(new Signer(self::SECRET)))->issue($this->context())['nonce'];
        $foreign = new Verifier(new Signer('a-completely-different-secret'));

        $this->assertFalse($foreign->verify($issued, $this->context()));
    }

    public function testVerifyRejectsCrossType(): void
    {
        $signer = new Signer(self::SECRET);
        $verifier = new Verifier($signer);

        // A clearance-type token is authentically signed and context-bound but is
        // not a challenge nonce — it must not verify as one.
        $clr = $signer->sign([
            'typ' => 'clr',
            'pid' => 'proj-123',
            'aud' => 'api',
            'iph' => $signer->fingerprintIp('203.0.113.9'),
            'iat' => \time(),
            'exp' => \time() + 600,
        ]);

        $this->assertFalse($verifier->verify($clr, $this->context()));
    }

    public function testNonceCarriesClearanceTtlRoundTrip(): void
    {
        $issuer = new Issuer(new Signer(self::SECRET));

        // No ttl requested -> nonce carries none.
        $plain = $issuer->issue($this->context());
        $this->assertNull($issuer->clearanceTtl($plain['nonce']));

        // Requested ttl is carried verbatim inside the signed nonce.
        $withTtl = $issuer->issue($this->context(), 1800);
        $this->assertSame(1800, $issuer->clearanceTtl($withTtl['nonce']));

        // A tampered nonce yields no ttl (signature no longer parses).
        $this->assertNull($issuer->clearanceTtl($withTtl['nonce'] . 'x'));
    }

    public function testKeyRotationHonorsNonceKid(): void
    {
        // Issue under kid 2, then rotate: kid 3 primary, kid 2 kept as previous.
        $issued = (new Issuer(new Signer(self::SECRET, 2)))->issue($this->context())['nonce'];

        $rotated = new Verifier(new Signer('new-secret', 3, [2 => self::SECRET]));
        $this->assertTrue($rotated->verify($issued, $this->context()));
    }
}
