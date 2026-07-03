<?php

namespace Utopia\WAF\Tests\Challenge;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Challenge\Scoring\AttackScore;

class AttackScoreTest extends TestCase
{
    public function testNormalizesAnomalyPoints(): void
    {
        $this->assertSame(0.0, AttackScore::normalize(0));
        $this->assertSame(0.0, AttackScore::normalize(-3)); // defensive
        $this->assertSame(0.5, AttackScore::normalize(5));  // one CRS critical
        $this->assertSame(1.0, AttackScore::normalize(10)); // ~2× threshold = certain
        $this->assertSame(1.0, AttackScore::normalize(40)); // capped
    }
}
