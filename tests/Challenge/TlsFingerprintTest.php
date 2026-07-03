<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Scoring\TlsFingerprint;

class TlsFingerprintTest extends TestCase
{
    private const CURL = 't13d311200_e8f1e7e78f70_b26ce05bbdd6';
    private const CHROME = 't13d1516h2_8daaf6152771_b186095e22b6';
    private const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';

    public function testKnownAutomationFingerprintIsAMismatchRegardlessOfUa(): void
    {
        $tls = new TlsFingerprint();
        $this->assertTrue($tls->mismatches(self::CURL, 'curl/8.5.0'));
        // the key case: a library TLS stack forging a browser User-Agent is still caught
        $this->assertTrue($tls->mismatches(self::CURL, self::CHROME_UA));
    }

    public function testRealBrowserPasses(): void
    {
        $tls = new TlsFingerprint();
        $this->assertFalse($tls->mismatches(self::CHROME, self::CHROME_UA));
    }

    public function testBrowserUaWithUnknownFingerprintIsSpoofing(): void
    {
        // UA claims a browser but the JA4 is not a known browser fingerprint
        $tls = new TlsFingerprint();
        $this->assertTrue($tls->mismatches('t13d0304i0_aaaaaaaaaaaa_bbbbbbbbbbbb', self::CHROME_UA));
    }

    public function testHonestNonBrowserClientIsNotAMismatch(): void
    {
        // an unknown fingerprint whose UA does NOT claim a browser is not flagged
        // by this signal (it may still be caught by other signals)
        $tls = new TlsFingerprint();
        $this->assertFalse($tls->mismatches('t13d0304i0_aaaaaaaaaaaa_bbbbbbbbbbbb', 'MyServerSDK/1.0'));
    }

    public function testEmptyFingerprintYieldsNoSignal(): void
    {
        $this->assertFalse((new TlsFingerprint())->mismatches('', self::CHROME_UA));
    }

    public function testCustomBlocklist(): void
    {
        $tls = new TlsFingerprint(automation: ['t13dXXXX_aaa_bbb'], browsers: []);
        $this->assertTrue($tls->mismatches('t13dXXXX_aaa_bbb', 'anything'));
        $this->assertFalse($tls->mismatches(self::CURL, 'curl/8.5.0')); // default seed not applied
    }
}
