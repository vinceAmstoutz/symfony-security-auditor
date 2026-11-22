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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * Drops the reviewer feedback a provider froze for one run when the next run
 * begins, so a long-lived process (`mcp:serve`) never serves later audits the
 * first run's feedback.
 */
interface ReviewerFeedbackSnapshotInterface
{
    public function resetForNewRun(): void;
}
