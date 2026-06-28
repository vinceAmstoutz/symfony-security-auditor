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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Test fake — records every progress event emitted by the pipeline.
 *
 * @internal scoped to AuditPipelineTest
 */
final class RecordingProgressReporter implements ProgressReporterInterface
{
    /** @var list<array{0: string, 1: array<string, mixed>}> */
    public array $events = [];

    #[Override]
    public function report(string $event, array $context = []): void
    {
        $this->events[] = [$event, $context];
    }
}
