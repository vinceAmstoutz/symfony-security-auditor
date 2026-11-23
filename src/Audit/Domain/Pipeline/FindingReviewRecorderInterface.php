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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Optional companion of {@see CoverageRecorderInterface}, checked with
 * `instanceof`: ties each reviewer entry to its finding, so a later verdict on
 * that finding supersedes an earlier failure.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface FindingReviewRecorderInterface
{
    public function recordFindingReview(Vulnerability $vulnerability, string $status): void;
}
