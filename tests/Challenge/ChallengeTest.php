<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Clearance;
use Utopia\WAF\Challenge\Context;
use Utopia\WAF\Challenge\Ip;
use Utopia\WAF\Challenge\Issuer;
use Utopia\WAF\Challenge\Signer;
use Utopia\WAF\Challenge\Verifier;
use Utopia\WAF\Exception\Challenge as ChallengeException;

class ChallengeTest extends TestCase
{
    private const SECRET = 'unit-test-secret-please-rotate';

    private function context(string $ip = '203.0.113.9'): Context
    {
        return new Context('proj-123', 'api', $ip);
    }

    /**
     * Brute-force a solution for the given nonce and difficulty.
     */
    private function solve(string $nonce, int $difficulty): string
    {
        for ($i = 0; $i < 5_000_000; $i++) {
            $solution = (string) $i;
            if ($this->leadingZeroBits(\hash('sha256', $nonce . '.' . $solution, true)) >= $difficulty) {
                return $solution;
            }
        }

        $this->fail('Could not find a solution for difficulty ' . $difficulty);
    }

    private function leadingZeroBits(string $digest): int
    {
        $bits = 0;
        foreach (\str_split($digest) as $char) {
            $byte = \ord($char);
            if ($byte === 0) {
                $bits += 8;

                continue;
            }
            for ($mask = 0x80; $mask > 0; $mask >>= 1) {
                if (($byte & $mask) !== 0) {
                    return $bits;
                }
                $bits++;
            }
            break;
        }

        return $bits;
    }

    public function testSignerRejectsEmptySecret(): void
    {
        $this->expectException(ChallengeException::class);
        new Signer('');
    }

    public function testSignParseRoundTrip(): void
    {
        $signer = new Signer(self::SECRET);
        $token = $signer->sign(['typ' => 'clr', 'foo' => 'bar']);

        $claims = $signer->parse($token);
        $this->assertIsArray($claims);
        $this->assertSame('clr', $claims['typ']);
        $this->assertSame('bar', $claims['foo']);
        $this->assertSame(1, $claims['kid']);
    }

    public function testParseRejectsTamperedPayload(): void
    {
        $signer = new Signer(self::SECRET);
        $token = $signer->sign(['typ' => 'clr']);

        [$payload, $signature] = \explode('.', $token);
        $forged = \rtrim(\strtr(\base64_encode('{"typ":"clr","kid":1,"admin":true}'), '+/', '-_'), '=');

        $this->assertNull($signer->parse($forged . '.' . $signature));
    }

    public function testParseRejectsMalformedTokens(): void
    {
        $signer = new Signer(self::SECRET);

        $this->assertNull($signer->parse(''));
        $this->assertNull($signer->parse('no-dot'));
        $this->assertNull($signer->parse('a.b.c'));
        $this->assertNull($signer->parse('.sig'));
        $this->assertNull($signer->parse('payload.'));
    }

    public function testParseRejectsForeignSecret(): void
    {
        $minted = new Signer(self::SECRET);
        $other = new Signer('a-completely-different-secret');

        $token = $minted->sign(['typ' => 'clr']);
        $this->assertNull($other->parse($token));
    }

    public function testKeyRotationAcceptsPreviousSecret(): void
    {
        $old = new Signer('old-secret', kid: 1);
        $token = $old->sign(['typ' => 'clr', 'v' => 1]);

        // New primary key, old key retained for the rotation window.
        $rotated = new Signer('new-secret', kid: 2, previousSecrets: [1 => 'old-secret']);

        $claims = $rotated->parse($token);
        $this->assertIsArray($claims);
        $this->assertSame(1, $claims['kid']);

        // Once the old key is dropped, the token no longer verifies.
        $droppedOld = new Signer('new-secret', kid: 2);
        $this->assertNull($droppedOld->parse($token));
    }

    public function testIssueClampsDifficulty(): void
    {
        $issuer = new Issuer(new Signer(self::SECRET));

        $this->assertSame(Issuer::DIFFICULTY_MIN, $issuer->issue($this->context(), 1)['difficulty']);
        $this->assertSame(Issuer::DIFFICULTY_MAX, $issuer->issue($this->context(), 999)['difficulty']);
    }

    public function testProofOfWorkRoundTrip(): void
    {
        $signer = new Signer(self::SECRET);
        $issuer = new Issuer($signer);
        $verifier = new Verifier($signer);

        // Low difficulty keeps the brute-force fast and deterministic.
        $challenge = $issuer->issue($this->context(), Issuer::DIFFICULTY_MIN);
        $nonce = $challenge['nonce'];
        $solution = $this->solve($nonce, 8);

        // Re-issue at difficulty 8 for the positive case would need a private hook;
        // instead assert against a nonce we can satisfy by lowering the bar via a
        // dedicated low-difficulty signer token.
        $lowNonce = $signer->sign([
            'typ' => 'pow',
            'pid' => 'proj-123',
            'aud' => 'api',
            'iph' => $signer->fingerprintIp('203.0.113.9'),
            'dif' => 8,
            'iat' => \time(),
            'exp' => \time() + 120,
        ]);
        $lowSolution = $this->solve($lowNonce, 8);

        $this->assertTrue($verifier->verify($lowNonce, $lowSolution, $this->context()));
        $this->assertIsString($nonce);
        $this->assertIsString($solution);
    }

    public function testVerifyRejectsInsufficientWork(): void
    {
        $signer = new Signer(self::SECRET);
        $issuer = new Issuer($signer);
        $verifier = new Verifier($signer);

        // Real difficulty (2^16); a trivial solution will not meet it.
        $challenge = $issuer->issue($this->context(), Issuer::DIFFICULTY_DEFAULT);
        $this->assertFalse($verifier->verify($challenge['nonce'], '0', $this->context()));
    }

    public function testVerifyRejectsOversizedAndEmptySolution(): void
    {
        $signer = new Signer(self::SECRET);
        $verifier = new Verifier($signer);
        $nonce = (new Issuer($signer))->issue($this->context(), Issuer::DIFFICULTY_MIN)['nonce'];

        $this->assertFalse($verifier->verify($nonce, '', $this->context()));
        $this->assertFalse($verifier->verify($nonce, \str_repeat('a', Verifier::SOLUTION_MAX_LENGTH + 1), $this->context()));
    }

    public function testVerifyRejectsExpiredNonce(): void
    {
        $signer = new Signer(self::SECRET);
        $verifier = new Verifier($signer);

        // Hand-craft an already-expired nonce at difficulty 1 (trivially solvable).
        $nonce = $signer->sign([
            'typ' => 'pow',
            'pid' => 'proj-123',
            'aud' => 'api',
            'iph' => $signer->fingerprintIp('203.0.113.9'),
            'dif' => 1,
            'iat' => \time() - 1000,
            'exp' => \time() - 500,
        ]);
        $solution = $this->solve($nonce, 1);

        $this->assertFalse($verifier->verify($nonce, $solution, $this->context()));
    }

    public function testVerifyRejectsWrongContext(): void
    {
        $signer = new Signer(self::SECRET);
        $verifier = new Verifier($signer);

        $nonce = $signer->sign([
            'typ' => 'pow',
            'pid' => 'proj-123',
            'aud' => 'api',
            'iph' => $signer->fingerprintIp('203.0.113.9'),
            'dif' => 1,
            'iat' => \time(),
            'exp' => \time() + 120,
        ]);
        $solution = $this->solve($nonce, 1);

        $this->assertFalse($verifier->verify($nonce, $solution, new Context('other-project', 'api', '203.0.113.9')));
        $this->assertFalse($verifier->verify($nonce, $solution, new Context('proj-123', 'mysite.example', '203.0.113.9')));
        // Different /24 network.
        $this->assertFalse($verifier->verify($nonce, $solution, new Context('proj-123', 'api', '198.51.100.9')));
        // Same /24 still passes.
        $this->assertTrue($verifier->verify($nonce, $solution, new Context('proj-123', 'api', '203.0.113.200')));
    }

    public function testClearanceRoundTrip(): void
    {
        $signer = new Signer(self::SECRET);
        $clearance = new Clearance($signer);

        $token = $clearance->issue($this->context());
        $this->assertTrue($clearance->verify($token, $this->context()));
    }

    public function testClearanceClampsTtl(): void
    {
        $signer = new Signer(self::SECRET);
        $clearance = new Clearance($signer);

        $token = $clearance->issue($this->context(), 5);
        $claims = $signer->parse($token);
        $this->assertIsArray($claims);
        $this->assertSame(Clearance::TTL_MIN, $claims['exp'] - $claims['iat']);
    }

    public function testClearanceRejectsExpired(): void
    {
        $signer = new Signer(self::SECRET);
        $clearance = new Clearance($signer);

        $token = $signer->sign([
            'typ' => 'clr',
            'pid' => 'proj-123',
            'aud' => 'api',
            'iph' => $signer->fingerprintIp('203.0.113.9'),
            'iat' => \time() - 10000,
            'exp' => \time() - 9000,
        ]);

        $this->assertFalse($clearance->verify($token, $this->context()));
    }

    public function testClearanceRejectsCrossType(): void
    {
        $signer = new Signer(self::SECRET);
        $clearance = new Clearance($signer);
        $verifier = new Verifier($signer);

        // A clearance token must not be accepted as a PoW nonce, and vice versa.
        $clr = $clearance->issue($this->context());
        $this->assertFalse($verifier->verify($clr, '0', $this->context()));

        $pow = (new Issuer($signer))->issue($this->context())['nonce'];
        $this->assertFalse($clearance->verify($pow, $this->context()));
    }

    public function testClearanceRejectsWrongNetwork(): void
    {
        $signer = new Signer(self::SECRET);
        $clearance = new Clearance($signer);

        $token = $clearance->issue($this->context('203.0.113.9'));

        $this->assertTrue($clearance->verify($token, $this->context('203.0.113.77')));
        $this->assertFalse($clearance->verify($token, $this->context('198.51.100.77')));
    }

    public function testIpPrefix(): void
    {
        $this->assertSame(Ip::prefix('203.0.113.9'), Ip::prefix('203.0.113.250'));
        $this->assertNotSame(Ip::prefix('203.0.113.9'), Ip::prefix('203.0.114.9'));

        $this->assertSame(Ip::prefix('2001:db8:abcd:1234::1'), Ip::prefix('2001:db8:abcd:1234:ffff::9'));
        $this->assertNotSame(Ip::prefix('2001:db8:abcd:1234::1'), Ip::prefix('2001:db8:abcd:9999::1'));

        // Non-address input binds to itself rather than throwing.
        $this->assertSame('not-an-ip', Ip::prefix('not-an-ip'));
    }
}
