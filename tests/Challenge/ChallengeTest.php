<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Context;
use Utopia\WAF\Challenge\Issuer;
use Utopia\WAF\Challenge\SilentChallenge;
use Utopia\WAF\Challenge\Signer;
use Utopia\WAF\Challenge\Verifier;

/**
 * Silent-tier tests: the invisible challenge issue -> verify path (Issuer,
 * Verifier) and its underlying primitive (SilentChallenge). The token core it
 * builds on (Signer/Clearance/Context/Ip) lives in and is tested by the captcha
 * leaf; here we drive the silent challenge that sits next to the scoring engine.
 */
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

    /**
     * Brute-force a memory-hard solution (romix digest) for the given nonce.
     */
    private function solveMemoryHard(string $nonce, int $difficulty, int $memory): string
    {
        for ($i = 0; $i < 5_000_000; $i++) {
            $solution = (string) $i;
            if (SilentChallenge::meets($nonce . '.' . $solution, $difficulty, $memory)) {
                return $solution;
            }
        }

        $this->fail('Could not find a memory-hard solution for difficulty ' . $difficulty);
    }

    public function testIssueClampsDifficulty(): void
    {
        $issuer = new Issuer(new Signer(self::SECRET));

        $this->assertSame(Issuer::DIFFICULTY_MIN, $issuer->issue($this->context(), 1)['difficulty']);
        $this->assertSame(Issuer::DIFFICULTY_MAX, $issuer->issue($this->context(), 999)['difficulty']);
    }

    public function testChallengeRoundTrip(): void
    {
        $signer = new Signer(self::SECRET);
        $issuer = new Issuer($signer);
        $verifier = new Verifier($signer);

        // Drive the real Issuer -> Verifier path at the clamped minimum
        // difficulty (2^16 ~ 65k hashes, well under a second).
        $challenge = $issuer->issue($this->context(), Issuer::DIFFICULTY_MIN);
        $this->assertSame(Issuer::DIFFICULTY_MIN, $challenge['difficulty']);
        $this->assertSame(Issuer::ALGORITHM, $challenge['algorithm']);
        $this->assertSame(Issuer::NONCE_TTL, $challenge['expiresIn']);
        $this->assertSame($challenge['expiresIn'], $challenge['expiresAt'] - \time());

        $solution = $this->solve($challenge['nonce'], $challenge['difficulty']);

        $this->assertTrue($verifier->verify($challenge['nonce'], $solution, $this->context()));
    }

    public function testMemoryHardChallengeRoundTrip(): void
    {
        $signer = new Signer(self::SECRET);
        $issuer = new Issuer($signer);
        $verifier = new Verifier($signer);

        // A memory-hard challenge advertises the romix algorithm, carries the
        // memory cost in the (signed) nonce, and clamps the difficulty into the
        // lower memory-mode band even though a classic-range value was requested.
        $memory = 64; // small scratchpad keeps the test fast
        $challenge = $issuer->issue($this->context(), Issuer::DIFFICULTY_DEFAULT, null, $memory);

        $this->assertSame(SilentChallenge::ALGORITHM_ROMIX, $challenge['algorithm']);
        $this->assertSame($memory, $challenge['memory']);
        $this->assertLessThanOrEqual(Issuer::MEMORY_DIFFICULTY_MAX, $challenge['difficulty']);
        $this->assertGreaterThanOrEqual(Issuer::MEMORY_DIFFICULTY_MIN, $challenge['difficulty']);

        // Solve with the memory-aware digest, then verify through the real path.
        $solution = $this->solveMemoryHard($challenge['nonce'], $challenge['difficulty'], $memory);
        $this->assertTrue($verifier->verify($challenge['nonce'], $solution, $this->context()));

        // The memory-hard and classic digests of the same input are independent
        // functions, so the mode baked into the (signed) nonce cannot be downgraded.
        $this->assertNotSame(
            SilentChallenge::digest($challenge['nonce'] . '.' . $solution, $memory),
            SilentChallenge::digest($challenge['nonce'] . '.' . $solution, 0),
        );
    }

    public function testMemoryDifficultyTranslatesFromCpuBand(): void
    {
        $issuer = new Issuer(new Signer(self::SECRET));

        // A CPU-band difficulty is mapped proportionally onto the memory band
        // instead of being re-clamped to the band maximum, so the rule knob and
        // the adaptive ladder keep their effect. Band edges and midpoint:
        $cases = [
            Issuer::DIFFICULTY_MIN => Issuer::MEMORY_DIFFICULTY_MIN,      // 16 -> 4
            20 => 8,                                                       // midpoint
            Issuer::DIFFICULTY_MAX => Issuer::MEMORY_DIFFICULTY_MAX,      // 24 -> 12
        ];

        foreach ($cases as $cpu => $expected) {
            $challenge = $issuer->issue($this->context(), $cpu, null, 256);
            $this->assertSame($expected, $challenge['difficulty'], "cpu {$cpu} should map to {$expected}");
        }

        // The default difficulty must not pin to the band maximum.
        $default = $issuer->issue($this->context(), Issuer::DIFFICULTY_DEFAULT, null, 256);
        $this->assertLessThan(Issuer::MEMORY_DIFFICULTY_MAX, $default['difficulty']);
    }

    public function testNonceCarriesClearanceTtlRoundTrip(): void
    {
        $signer = new Signer(self::SECRET);
        $issuer = new Issuer($signer);

        // No ttl requested -> nonce carries none.
        $plain = $issuer->issue($this->context(), Issuer::DIFFICULTY_MIN);
        $this->assertNull($issuer->clearanceTtl($plain['nonce']));

        // Requested ttl is carried verbatim inside the signed nonce so the solve
        // endpoint can honour the rule's configured lifetime.
        $challenge = $issuer->issue($this->context(), Issuer::DIFFICULTY_MIN, 1800);
        $this->assertSame(1800, $issuer->clearanceTtl($challenge['nonce']));

        // A tampered nonce yields no ttl (signature no longer parses).
        $this->assertNull($issuer->clearanceTtl($challenge['nonce'] . 'x'));
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
            'typ' => 'challenge',
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
            'typ' => 'challenge',
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
}
