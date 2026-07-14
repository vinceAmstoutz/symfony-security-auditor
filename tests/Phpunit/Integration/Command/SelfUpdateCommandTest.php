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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Command\SelfUpdateCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\RecordingSelfUpdater;

final class SelfUpdateCommandTest extends TestCase
{
    public function test_it_reports_a_successful_update(): void
    {
        $commandTester = $this->commandTester(new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::Updated, '1.0.0', '2.0.0')));

        $commandTester->execute([]);

        self::assertStringContainsString('Updated from 1.0.0 to 2.0.0', $commandTester->getDisplay());
    }

    public function test_it_reports_when_already_up_to_date(): void
    {
        $commandTester = $this->commandTester(new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::AlreadyUpToDate, '2.0.0', '2.0.0')));

        $commandTester->execute([]);

        self::assertStringContainsString('Already up to date', $commandTester->getDisplay());
    }

    public function test_it_reports_an_available_update_in_check_mode(): void
    {
        $recordingSelfUpdater = new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::UpdateAvailable, '1.0.0', '2.0.0'));

        $this->commandTester($recordingSelfUpdater)->execute(['--check' => true]);

        self::assertTrue($recordingSelfUpdater->checkOnly);
    }

    public function test_it_runs_a_real_update_by_default(): void
    {
        $recordingSelfUpdater = new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::Updated, '3.1.4', '4.0.0'));

        $this->commandTester($recordingSelfUpdater, '3.1.4')->execute([]);

        self::assertFalse($recordingSelfUpdater->checkOnly);
        self::assertSame('3.1.4', $recordingSelfUpdater->currentVersion);
    }

    public function test_it_reports_a_success_exit_code(): void
    {
        $commandTester = $this->commandTester(new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::Updated, '1.0.0', '2.0.0')));

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));
    }

    private function commandTester(RecordingSelfUpdater $recordingSelfUpdater, string $currentVersion = '1.0.0'): CommandTester
    {
        return new CommandTester(new SelfUpdateCommand($recordingSelfUpdater, $currentVersion));
    }
}
