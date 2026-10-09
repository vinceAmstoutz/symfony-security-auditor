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
 * Opt-in companion of {@see CoverageRecorderInterface} for a recorder that
 * ties each reviewer coverage entry to the finding it is about, so a verdict
 * (`validated` or `rejected`) reached for a finding in a later iteration
 * supersedes a failure (`errored`, `aborted`) recorded for that same finding
 * earlier instead of leaving the report incomplete for good. The reviewer
 * checks for it with `instanceof`, so a recorder without it keeps working.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface FindingReviewRecorderInterface
{
    public function recordFindingReview(Vulnerability $vulnerability, string $status): void;
}
