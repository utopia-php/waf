<?php

namespace Utopia\WAF\Challenge;

/**
 * Immutable per-request context a challenge is bound to.
 *
 * A clearance minted for one context is only valid for the same context, so a
 * solved challenge cannot be replayed across projects, surfaces, or networks.
 */
final readonly class Context
{
    /**
     * @param string $projectId project the challenge belongs to
     * @param string $audience  surface the clearance is scoped to (e.g. 'api' or a hostname)
     * @param string $ip        client IP; only its network prefix is bound (see Ip::prefix())
     */
    public function __construct(
        public string $projectId,
        public string $audience,
        public string $ip,
    ) {
    }
}
