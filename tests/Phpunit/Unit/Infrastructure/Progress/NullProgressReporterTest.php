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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;

final class NullProgressReporterTest extends TestCase
{
    public function test_report_discards_every_event_without_throwing(): void
    {
        $nullProgressReporter = new NullProgressReporter();

        $this->expectOutputString('');

        $nullProgressReporter->report('pipeline.started', ['audit_id' => 'X']);
        $nullProgressReporter->report('stage.completed', []);
    }
}
