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

/**
 * Optional companion of {@see CoverageRecorderInterface}, checked with
 * `instanceof`: keeps why a file ended `errored`, so progress output names the
 * cause of a failed chunk.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface FailureReasonRecorderInterface
{
    public function recordFailureReason(string $stage, string $filePath, string $reason): void;
}
