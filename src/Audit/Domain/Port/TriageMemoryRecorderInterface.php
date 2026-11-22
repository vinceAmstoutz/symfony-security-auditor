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
 * Records the reason the reviewer gave for rejecting a finding, which a later
 * run's {@see ReviewerFeedbackProviderInterface} hands back to the reviewer as
 * a negative example.
 */
interface TriageMemoryRecorderInterface
{
    public function record(string $type, string $file, string $title, int $line, string $reason): void;
}
