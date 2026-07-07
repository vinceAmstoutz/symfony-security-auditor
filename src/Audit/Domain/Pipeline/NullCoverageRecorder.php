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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

final readonly class NullCoverageRecorder implements CoverageRecorderInterface
{
    #[Override]
    public function recordCoverage(string $stage, string $filePath, string $status): void
    {
        // intentionally noop
    }

    #[Override]
    public function recordReviewedFinding(Vulnerability $vulnerability): void
    {
        // intentionally noop
    }

    #[Override]
    public function drainReviewedFindings(): array
    {
        return [];
    }

    #[Override]
    public function recordFoundVulnerability(Vulnerability $vulnerability): void
    {
        // intentionally noop
    }

    #[Override]
    public function drainFoundVulnerabilities(): array
    {
        return [];
    }
}
