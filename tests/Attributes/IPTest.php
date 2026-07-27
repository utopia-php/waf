<?php

namespace Utopia\WAF\Tests\Attributes;

use PHPUnit\Framework\TestCase;
use Utopia\WAF\Condition;
use Utopia\WAF\Attributes\IP;

class IPTest extends TestCase
{
    private IP $type;

    protected function setUp(): void
    {
        $this->type = new IP();
    }

    public function testCompareHandlesCidrValues(): void
    {
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '10.0.0.0/8'));
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '10.255.255.255', '10.0.0.0/8'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '11.0.0.0', '10.0.0.0/8'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '9.255.255.255', '10.0.0.0/8'));
    }

    public function testCompareHandlesNonOctetAlignedPrefixes(): void
    {
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '192.168.31.255', '192.168.16.0/20'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '192.168.32.0', '192.168.16.0/20'));
    }

    public function testCompareHandlesHostAndCatchAllPrefixes(): void
    {
        // /32 is an exact host match.
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '203.0.113.10', '203.0.113.10/32'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '203.0.113.11', '203.0.113.10/32'));

        // Everything matches /0.
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '203.0.113.10', '0.0.0.0/0'));

        // Host bits set in the CIDR are masked away.
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '10.200.0.1', '10.1.2.3/8'));
    }

    public function testCompareHandlesIpv6(): void
    {
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '2001:db8::1', '2001:db8::/32'));
        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', '2001:db8::/32'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '2001:db9::1', '2001:db8::/32'));

        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '::1', '::1/128'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '::2', '::1/128'));

        $this->assertTrue($this->type->compare(Condition::TYPE_EQUAL, '2001:db8::1', '::/0'));
    }

    public function testCompareRejectsFamilyMismatch(): void
    {
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '2001:db8::1', '10.0.0.0/8'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '2001:db8::/32'));
    }

    public function testCompareFallsBackForPlainIps(): void
    {
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '10.0.0.1'));
    }

    public function testCompareFallsBackForMalformedCidrValues(): void
    {
        // Not valid CIDR blocks -> not handled, default string equality applies.
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '10.0.0.0/33'));
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '2001:db8::/129'));
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '10.0.0.0/'));
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '10.0.0.0/-1'));
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '10.0.0.0/8.5'));
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', 'not-an-ip/8'));
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', '/8'));
        $this->assertNull($this->type->compare(Condition::TYPE_EQUAL, '10.0.0.1', ''));
    }

    public function testCompareFallsBackForOtherMethods(): void
    {
        $this->assertNull($this->type->compare(Condition::TYPE_CONTAINS, '10.0.0.1', '10.0.0.0/8'));
        $this->assertNull($this->type->compare(Condition::TYPE_STARTS_WITH, '10.0.0.1', '10.0.0.0/8'));
    }

    public function testCompareRejectsNonStringValuesAgainstCidr(): void
    {
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, null, '10.0.0.0/8'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, 42, '10.0.0.0/8'));
        $this->assertFalse($this->type->compare(Condition::TYPE_EQUAL, 'not-an-ip', '10.0.0.0/8'));
    }

    public function testValidateValue(): void
    {
        $this->assertNull($this->type->validateValue(Condition::TYPE_EQUAL, '203.0.113.10'));
        $this->assertNull($this->type->validateValue(Condition::TYPE_EQUAL, '10.0.0.0/8'));
        $this->assertNull($this->type->validateValue(Condition::TYPE_NOT_EQUAL, '2001:db8::/32'));

        $this->assertNotNull($this->type->validateValue(Condition::TYPE_EQUAL, '10.0.0.0/33'));
        $this->assertNotNull($this->type->validateValue(Condition::TYPE_EQUAL, 'not-an-ip'));
        $this->assertNotNull($this->type->validateValue(Condition::TYPE_EQUAL, 42));

        // Operators outside equality are not value-restricted by this type.
        $this->assertNull($this->type->validateValue(Condition::TYPE_IS_NULL, 'anything'));
    }
}
