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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;

/**
 * Test fake: a reviewer cache that always misses and keeps every verdict it
 * is asked to store in a public buffer, so a test can assert what was — and
 * was not — persisted without mocking the port.
 */
final class RecordingReviewerCache implements ReviewerCacheInterface
{
    /** @var list<array<string, mixed>> */
    public array $stored = [];

    #[Override]
    public function get(Vulnerability $vulnerability, string $codeContext): ?array
    {
        return null;
    }

    #[Override]
    public function store(Vulnerability $vulnerability, string $codeContext, array $review): void
    {
        $this->stored[] = $review;
    }
}
