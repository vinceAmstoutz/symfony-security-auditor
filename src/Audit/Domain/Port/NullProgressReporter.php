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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Default reporter — discards every event. Used when the host has not
 * registered a custom reporter, so the pipeline can emit events
 * unconditionally without paying any I/O cost.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NullProgressReporter implements ProgressReporterInterface
{
    public function report(string $event, array $context = []): void
    {
        // no-op
    }
}
