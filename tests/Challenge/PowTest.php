<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Pow;

class PowTest extends TestCase
{
    public function testAlgorithmLabelReflectsMemory(): void
    {
        $this->assertSame(Pow::ALGORITHM_SHA256, Pow::algorithm(0));
        $this->assertSame(Pow::ALGORITHM_SHA256, Pow::algorithm(-1));
        $this->assertSame(Pow::ALGORITHM_ROMIX, Pow::algorithm(1));
        $this->assertSame(Pow::ALGORITHM_ROMIX, Pow::algorithm(512));
    }

    public function testClassicDigestIsPlainSha256(): void
    {
        // memory <= 0 must be byte-identical to a plain SHA-256, so existing
        // (non-memory) challenges keep verifying exactly as before.
        $this->assertSame(\hash('sha256', 'abc', true), Pow::digest('abc', 0));
        $this->assertSame(\hash('sha256', 'abc', true), Pow::digest('abc', -5));
    }

    public function testRomixIsDeterministic(): void
    {
        $this->assertSame(Pow::romix('seed.1', 128), Pow::romix('seed.1', 128));
    }

    public function testRomixDiffersFromSha256AndAcrossMemory(): void
    {
        $input = 'challenge.42';
        $this->assertNotSame(\hash('sha256', $input, true), Pow::romix($input, 64));
        // Different scratchpad sizes are different functions.
        $this->assertNotSame(Pow::romix($input, 64), Pow::romix($input, 128));
    }

    public function testRomixOutputSize(): void
    {
        $this->assertSame(32, \strlen(Pow::romix('x', 1)));
        $this->assertSame(32, \strlen(Pow::romix('x', 256)));
    }

    public function testRomixMemoryOfOneIsDoubleHash(): void
    {
        // memory=1: V=[sha256(input)]; one mix round reads V[0], so the result is
        // sha256(sha256(input) XOR sha256(input)) = sha256(32 zero bytes).
        $expected = \hash('sha256', \str_repeat("\0", 32), true);
        $this->assertSame($expected, Pow::romix('anything at all', 1));
    }

    public function testLeadingZeroBitsCounts(): void
    {
        $this->assertSame(0, Pow::leadingZeroBits("\xff"));
        $this->assertSame(8, Pow::leadingZeroBits("\x00\xff"));
        $this->assertSame(9, Pow::leadingZeroBits("\x00\x7f"));
        $this->assertSame(16, Pow::leadingZeroBits("\x00\x00"));
    }

    public function testMeetsHonoursDifficultyAndMode(): void
    {
        // Find a small classic solution, then confirm meets() agrees and that the
        // same input under the memory-hard digest is an independent verdict.
        $nonce = 'pow-test-nonce';
        $difficulty = 8;

        $solution = null;
        for ($i = 0; $i < 5_000_000; $i++) {
            if (Pow::meets($nonce . '.' . $i, $difficulty, 0)) {
                $solution = (string) $i;
                break;
            }
        }

        $this->assertNotNull($solution, 'expected to find a classic solution');
        $this->assertTrue(Pow::meets($nonce . '.' . $solution, $difficulty, 0));
        // The memory-hard digest of the same input is an independent function, so
        // the modes cannot alias (deterministic check — no probabilistic verdict).
        $this->assertNotSame(
            Pow::digest($nonce . '.' . $solution, 0),
            Pow::digest($nonce . '.' . $solution, 512),
        );
    }
}
