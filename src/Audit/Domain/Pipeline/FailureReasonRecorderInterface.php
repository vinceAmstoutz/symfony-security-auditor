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
 * Opt-in companion of {@see CoverageRecorderInterface} for a recorder that
 * keeps why a file ended `errored` — the answer was cut short, the call failed
 * — so progress output can name the cause of a failed chunk instead of only
 * the fact. The analyzers check for it with `instanceof`, so a recorder
 * without it keeps working.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface FailureReasonRecorderInterface
{
    public function recordFailureReason(string $stage, string $filePath, string $reason): void;
}
