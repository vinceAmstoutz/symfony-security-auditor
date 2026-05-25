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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\NullProgressReporter;

final class NullProgressReporterTest extends TestCase
{
    public function test_implements_progress_reporter_contract(): void
    {
        self::assertInstanceOf(ProgressReporterInterface::class, new NullProgressReporter());
    }

    public function test_report_discards_every_event_without_throwing(): void
    {
        $nullProgressReporter = new NullProgressReporter();

        $nullProgressReporter->report('pipeline.started', ['audit_id' => 'X']);
        $nullProgressReporter->report('stage.completed', []);

        // No assertion needed beyond "does not throw"; the contract is that the
        // reporter is a no-op. Asserting on the type ensures the method exists.
        self::assertInstanceOf(NullProgressReporter::class, $nullProgressReporter);
    }
}
