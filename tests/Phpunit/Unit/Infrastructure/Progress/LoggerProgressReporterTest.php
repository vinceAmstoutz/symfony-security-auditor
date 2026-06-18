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
use Psr\Log\LoggerInterface;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\LoggerProgressReporter;

final class LoggerProgressReporterTest extends TestCase
{
    public function test_report_forwards_event_to_logger_at_info_level_with_audit_progress_prefix(): void
    {
        $calls = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$calls): void {
                $calls[] = [$msg, $ctx];
            },
        );

        $loggerProgressReporter = new LoggerProgressReporter($logger);
        $loggerProgressReporter->report('pipeline.started', ['audit_id' => 'X']);

        self::assertSame([['audit.progress: pipeline.started', ['audit_id' => 'X']]], $calls);
    }

    public function test_report_swallows_logger_exceptions(): void
    {
        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('info')->willThrowException(new RuntimeException('logger died'));

        $loggerProgressReporter = new LoggerProgressReporter($logger);

        $loggerProgressReporter->report('any.event');
    }
}
