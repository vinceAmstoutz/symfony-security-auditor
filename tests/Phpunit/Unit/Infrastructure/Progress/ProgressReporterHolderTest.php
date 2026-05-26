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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Progress;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;

final class ProgressReporterHolderTest extends TestCase
{
    public function test_it_is_silent_by_default(): void
    {
        $progressReporterHolder = new ProgressReporterHolder();
        $progressReporterHolder->report('pipeline.started', ['stages' => ['a']]);

        $reporter = $this->createMock(ProgressReporterInterface::class);
        $reporter->expects(self::never())->method('report');
        $progressReporterHolder->setDelegate($reporter);
    }

    public function test_it_delegates_to_set_reporter(): void
    {
        $progressReporterHolder = new ProgressReporterHolder();

        $reporter = $this->createMock(ProgressReporterInterface::class);
        $reporter->expects(self::once())
            ->method('report')
            ->with('stage.completed', []);

        $progressReporterHolder->setDelegate($reporter);
        $progressReporterHolder->report('stage.completed');
    }

    public function test_it_swallows_reporter_exceptions(): void
    {
        $progressReporterHolder = new ProgressReporterHolder();

        $throwing = self::createStub(ProgressReporterInterface::class);
        $throwing->method('report')->willThrowException(new RuntimeException('boom'));
        $progressReporterHolder->setDelegate($throwing);
        $progressReporterHolder->report('pipeline.completed');

        $working = $this->createMock(ProgressReporterInterface::class);
        $working->expects(self::once())->method('report')->with('stage.started', []);
        $progressReporterHolder->setDelegate($working);
        $progressReporterHolder->report('stage.started');
    }

    public function test_it_forwards_context_to_delegate(): void
    {
        $progressReporterHolder = new ProgressReporterHolder();
        $context = ['stage' => 'ingestion', 'audit_id' => 'abc'];

        $reporter = $this->createMock(ProgressReporterInterface::class);
        $reporter->expects(self::once())
            ->method('report')
            ->with('stage.started', $context);

        $progressReporterHolder->setDelegate($reporter);
        $progressReporterHolder->report('stage.started', $context);
    }
}
