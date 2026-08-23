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

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PricingCatalogRefreshOutcome;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateCheckState;
use VinceAmstoutz\SymfonySecurityAuditor\Command\SelfUpdateCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\InMemoryUpdateCheckStore;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\RecordingSelfUpdater;

final class SelfUpdateCommandTest extends TestCase
{
    public function test_it_reports_a_successful_update(): void
    {
        $commandTester = $this->commandTester(new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::Updated, '1.0.0', '2.0.0')));

        $commandTester->execute([]);

        self::assertStringContainsString('Updated from 1.0.0 to 2.0.0', $commandTester->getDisplay());
    }

    public function test_it_warns_when_the_pricing_catalog_could_not_be_refreshed(): void
    {
        $selfUpdateResult = new SelfUpdateResult(SelfUpdateStatus::Updated, '1.0.0', '2.0.0', PricingCatalogRefreshOutcome::Failed);
        $commandTester = $this->commandTester(new RecordingSelfUpdater($selfUpdateResult));

        $commandTester->execute([]);

        self::assertStringContainsString('Could not refresh the bundled pricing catalog', $commandTester->getDisplay());
    }

    public function test_it_stays_quiet_when_the_pricing_catalog_was_refreshed(): void
    {
        $selfUpdateResult = new SelfUpdateResult(SelfUpdateStatus::Updated, '1.0.0', '2.0.0', PricingCatalogRefreshOutcome::Refreshed);
        $commandTester = $this->commandTester(new RecordingSelfUpdater($selfUpdateResult));

        $commandTester->execute([]);

        self::assertStringNotContainsString('Could not refresh', $commandTester->getDisplay());
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

    public function test_it_clears_the_update_check_cache_after_a_successful_update(): void
    {
        $inMemoryUpdateCheckStore = new InMemoryUpdateCheckStore();
        $commandTester = $this->commandTester(
            new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::Updated, '1.0.0', '2.0.0')),
            inMemoryUpdateCheckStore: $inMemoryUpdateCheckStore,
        );

        $commandTester->execute([]);

        self::assertSame(1, $inMemoryUpdateCheckStore->clearCalls);
    }

    public function test_it_does_not_clear_the_update_check_cache_when_already_up_to_date(): void
    {
        $inMemoryUpdateCheckStore = new InMemoryUpdateCheckStore();
        $commandTester = $this->commandTester(
            new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::AlreadyUpToDate, '2.0.0', '2.0.0')),
            inMemoryUpdateCheckStore: $inMemoryUpdateCheckStore,
        );

        $commandTester->execute([]);

        self::assertSame(0, $inMemoryUpdateCheckStore->clearCalls);
    }

    public function test_it_does_not_clear_the_update_check_cache_in_check_mode(): void
    {
        $inMemoryUpdateCheckStore = new InMemoryUpdateCheckStore();
        $commandTester = $this->commandTester(
            new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::UpdateAvailable, '1.0.0', '2.0.0')),
            inMemoryUpdateCheckStore: $inMemoryUpdateCheckStore,
        );

        $commandTester->execute(['--check' => true]);

        self::assertSame(0, $inMemoryUpdateCheckStore->clearCalls);
    }

    public function test_it_records_the_version_check_mode_observed_so_the_passive_notice_agrees(): void
    {
        $inMemoryUpdateCheckStore = new InMemoryUpdateCheckStore();
        $commandTester = $this->commandTester(
            new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::UpdateAvailable, '1.0.0', '2.0.0')),
            inMemoryUpdateCheckStore: $inMemoryUpdateCheckStore,
        );

        $commandTester->execute(['--check' => true]);

        self::assertEquals(
            new UpdateCheckState(new DateTimeImmutable('2026-01-01 00:00:00'), '2.0.0'),
            $inMemoryUpdateCheckStore->read(),
        );
    }

    public function test_it_records_an_up_to_date_answer_so_a_stale_notice_stops(): void
    {
        $inMemoryUpdateCheckStore = new InMemoryUpdateCheckStore(new UpdateCheckState(new DateTimeImmutable('2025-01-01 00:00:00'), '9.9.9'));
        $commandTester = $this->commandTester(
            new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::AlreadyUpToDate, '2.0.0', '2.0.0')),
            inMemoryUpdateCheckStore: $inMemoryUpdateCheckStore,
        );

        $commandTester->execute([]);

        self::assertSame('2.0.0', $inMemoryUpdateCheckStore->read()?->latestVersion);
    }

    public function test_it_does_not_record_a_version_after_installing_an_update(): void
    {
        $inMemoryUpdateCheckStore = new InMemoryUpdateCheckStore();
        $commandTester = $this->commandTester(
            new RecordingSelfUpdater(new SelfUpdateResult(SelfUpdateStatus::Updated, '1.0.0', '2.0.0')),
            inMemoryUpdateCheckStore: $inMemoryUpdateCheckStore,
        );

        $commandTester->execute([]);

        self::assertNull($inMemoryUpdateCheckStore->read());
    }

    private function commandTester(RecordingSelfUpdater $recordingSelfUpdater, string $currentVersion = '1.0.0', ?InMemoryUpdateCheckStore $inMemoryUpdateCheckStore = null): CommandTester
    {
        return new CommandTester(new SelfUpdateCommand(
            $recordingSelfUpdater,
            $currentVersion,
            $inMemoryUpdateCheckStore ?? new InMemoryUpdateCheckStore(),
            new MockClock('2026-01-01 00:00:00'),
        ));
    }
}
