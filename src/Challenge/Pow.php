<?php

namespace Utopia\WAF\Challenge;

/**
 * The proof-of-work primitive shared by {@see Issuer} and {@see Verifier}: turn a
 * challenge input into a digest and test it against a difficulty (leading zero
 * bits). Two modes, selected by the `memory` parameter:
 *
 *  - `memory <= 0` — classic SHA-256 (`sha256(input)`). Cheap to compute and to
 *    verify; the search cost is CPU-only, so it parallelises freely on GPUs/ASICs.
 *
 *  - `memory > 0`  — a sequential **memory-hard** hash ({@see self::romix()}). Each
 *    solution attempt must fill and then randomly read a `memory`-block scratchpad
 *    (`memory * 32` bytes), so throughput is bounded by memory bandwidth, not core
 *    count. This narrows the gap between a browser solving one challenge and a
 *    botnet farm solving millions — the whole point of raising the cost floor.
 *
 * The function is defined byte-for-byte so the pure-JS solver (see
 * `reference/solver.js`, inlined into {@see Interstitial}) and this PHP verifier
 * agree exactly. It is intentionally built from SHA-256 alone (no Argon2/scrypt
 * dependency) so the browser side stays a dependency-free, CSP-inlinable script.
 */
final class Pow
{
    public const ALGORITHM_SHA256 = 'sha256';

    public const ALGORITHM_ROMIX = 'sha256-romix';

    /**
     * The algorithm label advertised to the client for the given memory setting.
     */
    public static function algorithm(int $memory): string
    {
        return $memory > 0 ? self::ALGORITHM_ROMIX : self::ALGORITHM_SHA256;
    }

    /**
     * Raw (binary) proof-of-work digest of `$input` under the given memory cost.
     */
    public static function digest(string $input, int $memory): string
    {
        if ($memory <= 0) {
            return \hash(self::ALGORITHM_SHA256, $input, true);
        }

        return self::romix($input, $memory);
    }

    /**
     * Whether `$input` is a valid solution at `$difficulty` leading zero bits.
     */
    public static function meets(string $input, int $difficulty, int $memory): bool
    {
        return self::leadingZeroBits(self::digest($input, $memory)) >= $difficulty;
    }

    /**
     * Sequential memory-hard hash (a SHA-256 ROMix, in the scrypt lineage).
     *
     * 1. Fill a scratchpad of `$memory` 32-byte blocks by iterated hashing —
     *    `V[0] = sha256(input)`, `V[i] = sha256(V[i-1])`.
     * 2. Mix for `$memory` rounds with **data-dependent** reads: the next index is
     *    derived from the current accumulator, so the whole scratchpad must stay
     *    resident (you cannot recompute a block on demand without redoing the
     *    chain). That data dependency is what makes it memory-hard rather than
     *    merely memory-using.
     *
     * @param int $memory number of 32-byte scratchpad blocks (> 0)
     */
    public static function romix(string $input, int $memory): string
    {
        $v = [];
        $v[0] = \hash(self::ALGORITHM_SHA256, $input, true);
        for ($i = 1; $i < $memory; $i++) {
            $v[$i] = \hash(self::ALGORITHM_SHA256, $v[$i - 1], true);
        }

        $x = $v[$memory - 1];
        for ($i = 0; $i < $memory; $i++) {
            // Big-endian uint32 of the first 4 bytes, mod scratchpad size.
            $j = (\ord($x[0]) << 24 | \ord($x[1]) << 16 | \ord($x[2]) << 8 | \ord($x[3])) % $memory;
            $x = \hash(self::ALGORITHM_SHA256, $x ^ $v[$j], true);
        }

        return $x;
    }

    /**
     * Count leading zero bits across the raw (binary) digest.
     */
    public static function leadingZeroBits(string $digest): int
    {
        $bits = 0;
        $length = \strlen($digest);

        for ($i = 0; $i < $length; $i++) {
            $byte = \ord($digest[$i]);

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
        }

        return $bits;
    }
}
