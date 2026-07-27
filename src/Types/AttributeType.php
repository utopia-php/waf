<?php

namespace Utopia\WAF\Types;

/**
 * AttributeType
 *
 * Typed matching semantics for a specific attribute (e.g. IP addresses).
 * Registered on the Firewall and consulted by conditions before falling
 * back to the default comparison logic.
 */
interface AttributeType
{
    /**
     * Attempt a typed comparison of an attribute value against an expected value.
     *
     * Tri-state contract:
     *   true  - handled, the value matches
     *   false - handled, the value definitively does not match (default comparison is skipped)
     *   null  - not handled, fall back to the default comparison semantics
     *
     * Probed for every non-logical operator except isNull/isNotNull. Negated
     * operators probe their positive counterpart (notEqual as equal, notContains
     * as contains, ...) with the negation applied by the engine, so a type only
     * implements the positive semantics. Any-of operators (equal, contains)
     * probe once per expected value; startsWith/endsWith and relational
     * operators probe with their single reference value; between/notBetween
     * probe once with the full [start, end] pair as $expected.
     */
    public function compare(string $method, mixed $value, mixed $expected): ?bool;

    /**
     * Validate a single expected value for a given operator at rule-creation time.
     *
     * Returns an error message, or null when the value is valid.
     */
    public function validateValue(string $method, mixed $expected): ?string;
}
