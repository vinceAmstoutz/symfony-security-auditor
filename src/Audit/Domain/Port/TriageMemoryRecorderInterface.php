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
 * Records a reviewer-rejected finding's own stated reason so a future run's
 * {@see ReviewerFeedbackProviderInterface} can surface it back to the
 * reviewer as a negative example — the reviewer's rejections becoming its
 * own cross-run memory, without requiring a maintainer to hand-curate a
 * baseline entry for every recurring false positive.
 */
interface TriageMemoryRecorderInterface
{
    public function record(string $type, string $file, string $title, string $reason): void;
}
