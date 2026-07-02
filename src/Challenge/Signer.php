<?php

namespace Utopia\WAF\Challenge;

use Utopia\WAF\Exception\Challenge as ChallengeException;

/**
 * Mints and verifies compact, self-authenticating tokens.
 *
 * A token is `base64url(json(claims)) . '.' . base64url(hmac_sha256(payload))`.
 * The HMAC covers the exact transmitted payload bytes (including the key id), so
 * a token carries everything needed to verify it and nothing is stored server-side.
 *
 * Key rotation: every token embeds the `kid` of the secret that signed it.
 * Provide superseded secrets via $previousSecrets so tokens minted just before a
 * rotation stay valid until they expire on their own.
 */
final class Signer
{
    /**
     * @var array<int, string> kid => secret, primary first
     */
    private array $keyset;

    /**
     * @param string             $secret          current signing secret
     * @param int                $kid             identifier for the current secret
     * @param array<int, string> $previousSecrets superseded secrets kept for the rotation window, keyed by their kid
     */
    public function __construct(
        #[\SensitiveParameter] private readonly string $secret,
        private readonly int $kid = 1,
        #[\SensitiveParameter] array $previousSecrets = [],
    ) {
        if ($secret === '') {
            throw new ChallengeException('Challenge signing secret must not be empty.');
        }

        foreach ($previousSecrets as $previousKid => $previousSecret) {
            if ($previousSecret === '') {
                throw new ChallengeException('Previous challenge secret for kid ' . $previousKid . ' must not be empty.');
            }
        }

        $this->keyset = [$kid => $secret] + $previousSecrets;
    }

    /**
     * Sign a claims set, stamping it with the current key id.
     *
     * @param array<string, mixed> $claims
     */
    public function sign(array $claims): string
    {
        $claims['kid'] = $this->kid;

        try {
            $json = \json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $exception) {
            throw new ChallengeException('Unable to encode challenge claims: ' . $exception->getMessage());
        }

        $payload = self::encode($json);
        $signature = self::encode($this->hmac($payload, $this->secret));

        return $payload . '.' . $signature;
    }

    /**
     * Verify a token's signature and return its claims, or null if the token is
     * malformed, signed with an unknown key, or tampered with.
     *
     * @return array<string, mixed>|null
     */
    public function parse(string $token): ?array
    {
        $parts = \explode('.', $token);
        if (\count($parts) !== 2) {
            return null;
        }

        [$payload, $signature] = $parts;
        if ($payload === '' || $signature === '') {
            return null;
        }

        $decoded = self::decode($payload);
        if ($decoded === null) {
            return null;
        }

        $claims = \json_decode($decoded, true);
        if (!\is_array($claims)) {
            return null;
        }

        $kid = $claims['kid'] ?? null;
        if (!\is_int($kid) || !isset($this->keyset[$kid])) {
            return null;
        }

        $expected = self::encode($this->hmac($payload, $this->keyset[$kid]));
        if (!\hash_equals($expected, $signature)) {
            return null;
        }

        return $claims;
    }

    /**
     * Derive a stable, privacy-preserving fingerprint of an IP's network prefix.
     *
     * Keyed with the signing secret so the value is meaningless in logs and
     * cannot be reversed to an address. Pass the token's own kid at verify time
     * so rotation does not invalidate the binding of already-issued tokens.
     */
    public function fingerprintIp(string $ip, ?int $kid = null): string
    {
        $kid ??= $this->kid;
        if (!isset($this->keyset[$kid])) {
            throw new ChallengeException('Unknown key id: ' . $kid);
        }

        return \substr(\hash_hmac('sha256', Ip::prefix($ip), $this->keyset[$kid]), 0, 16);
    }

    private function hmac(string $payload, string $secret): string
    {
        return \hash_hmac('sha256', $payload, $secret, true);
    }

    private static function encode(string $binary): string
    {
        return \rtrim(\strtr(\base64_encode($binary), '+/', '-_'), '=');
    }

    private static function decode(string $value): ?string
    {
        $decoded = \base64_decode(\strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
