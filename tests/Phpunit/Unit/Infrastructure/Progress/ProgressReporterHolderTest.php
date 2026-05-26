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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;

final class ProgressReporterHolderTest extends TestCase
{
    public function test_it_is_silent_by_default(): void
    {
        $holder = new ProgressReporterHolder();

        $holder->report('pipeline.started', ['stages' => ['a']]);

        self::assertTrue(true);
    }

    public function test_it_delegates_to_set_reporter(): void
    {
        $holder = new ProgressReporterHolder();

        $reporter = $this->createMock(ProgressReporterInterface::class);
        $reporter->expects(self::once())
            ->method('report')
            ->with('stage.completed', []);

        $holder->setDelegate($reporter);
        $holder->report('stage.completed');
    }

    public function test_it_swallows_reporter_exceptions(): void
    {
        $holder = new ProgressReporterHolder();

        $reporter = $this->createStub(ProgressReporterInterface::class);
        $reporter->method('report')->willThrowException(new \RuntimeException('boom'));

        $holder->setDelegate($reporter);

        $holder->report('pipeline.completed');

        self::assertTrue(true);
    }

    public function test_it_forwards_context_to_delegate(): void
    {
        $holder = new ProgressReporterHolder();
        $context = ['stage' => 'ingestion', 'audit_id' => 'abc'];

        $reporter = $this->createMock(ProgressReporterInterface::class);
        $reporter->expects(self::once())
            ->method('report')
            ->with('stage.started', $context);

        $holder->setDelegate($reporter);
        $holder->report('stage.started', $context);
    }
}
