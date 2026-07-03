<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Scoring\ClientSignals;
use Utopia\WAF\Challenge\Scoring\Signal;

class ClientSignalsTest extends TestCase
{
    public function testWebdriverIsNearCertainHeadless(): void
    {
        $s = ClientSignals::normalize(['webdriver' => true]);
        $this->assertSame(1.0, $s[Signal::HEADLESS]);
    }

    public function testSoftHeadlessTellsCombine(): void
    {
        $s = ClientSignals::normalize([
            'webdriver' => false,
            'plugins' => 0,
            'languages' => 0,
            'webglVendor' => 'Google SwiftShader',
        ]);
        $this->assertSame(1.0, $s[Signal::HEADLESS]); // 0.4 + 0.3 + 0.3
    }

    public function testRealBrowserLooksHuman(): void
    {
        $s = ClientSignals::normalize([
            'webdriver' => false,
            'plugins' => 3,
            'languages' => 2,
            'webglVendor' => 'NVIDIA Corporation',
            'automationFlags' => 0,
            'mouseMoves' => 20,
            'keyPresses' => 4,
            'interacted' => true,
        ]);
        $this->assertSame(0.0, $s[Signal::HEADLESS]);
        $this->assertSame(0.0, $s[Signal::AUTOMATION_FLAGS]);
        $this->assertSame(0.0, $s[Signal::BEHAVIORAL_RISK]);
        // INTERACTION_PASSED is never produced from the blob (unforgeable): it is
        // established server-side by verifying the interactive challenge.
        $this->assertArrayNotHasKey(Signal::INTERACTION_PASSED, $s);
    }

    public function testAutomationFlagsScale(): void
    {
        $this->assertSame(1.0, ClientSignals::normalize(['automationFlags' => 3])[Signal::AUTOMATION_FLAGS]);
        $this->assertSame(1.0, ClientSignals::normalize(['automationFlags' => 9])[Signal::AUTOMATION_FLAGS]); // capped
        $this->assertSame(0.0, ClientSignals::normalize(['automationFlags' => 0])[Signal::AUTOMATION_FLAGS]);
    }

    public function testBehavioralRiskFromInputActivity(): void
    {
        // no input at all — a script solving the PoW
        $this->assertSame(1.0, ClientSignals::normalize([])[Signal::BEHAVIORAL_RISK]);
        // plenty of input — human
        $this->assertSame(0.0, ClientSignals::normalize(['mouseMoves' => 10, 'keyPresses' => 2])[Signal::BEHAVIORAL_RISK]);
        // a little input — partial
        $risk = ClientSignals::normalize(['mouseMoves' => 3])[Signal::BEHAVIORAL_RISK];
        $this->assertGreaterThan(0.0, $risk);
        $this->assertLessThan(1.0, $risk);
    }

    public function testGarbageBlobDoesNotThrowAndStaysConservative(): void
    {
        $s = ClientSignals::normalize([
            'webdriver' => 'not-a-bool',
            'plugins' => 'x',
            'automationFlags' => ['nested'],
            'mouseMoves' => null,
        ]);
        $this->assertIsFloat($s[Signal::HEADLESS]);
        $this->assertSame(0.0, $s[Signal::AUTOMATION_FLAGS]);
        $this->assertSame(1.0, $s[Signal::BEHAVIORAL_RISK]);
        $this->assertArrayNotHasKey(Signal::INTERACTION_PASSED, $s);
    }

    public function testInteractionPassedIsNeverClientAsserted(): void
    {
        // No form of client-supplied `interacted` yields an interaction pass — the
        // whole point of moving the humanity secret server-side.
        foreach ([true, 1, 'true', 0, false] as $value) {
            $this->assertArrayNotHasKey(
                Signal::INTERACTION_PASSED,
                ClientSignals::normalize(['interacted' => $value]),
            );
        }
    }
}
