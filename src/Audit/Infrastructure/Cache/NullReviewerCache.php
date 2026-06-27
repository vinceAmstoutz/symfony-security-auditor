<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;

/**
 * No-op reviewer cache: every lookup misses and stores are discarded. Wired
 * when `cache.enabled` is false so the reviewer always calls the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NullReviewerCache implements ReviewerCacheInterface
{
    #[Override]
    public function get(Vulnerability $vulnerability, string $codeContext): ?array
    {
        return null;
    }

    #[Override]
    public function store(Vulnerability $vulnerability, string $codeContext, array $review): void {}
}
