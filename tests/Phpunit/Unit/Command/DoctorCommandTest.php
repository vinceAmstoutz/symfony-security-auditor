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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckResult;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\EnvironmentDoctorInterface;

final class DoctorCommandTest extends TestCase
{
    public function test_it_reports_success_when_no_check_fails(): void
    {
        $commandTester = $this->commandTester(
            new DoctorCheckResult('Configuration', DoctorCheckStatus::Ok, 'Config resolves.'),
            new DoctorCheckResult('Composer', DoctorCheckStatus::Warning, 'Not found.'),
        );

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));
    }

    public function test_it_reports_failure_when_any_check_fails(): void
    {
        $commandTester = $this->commandTester(
            new DoctorCheckResult('Configuration', DoctorCheckStatus::Ok, 'Config resolves.'),
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, 'Not installed.'),
        );

        self::assertSame(Command::FAILURE, $commandTester->execute([]));
    }

    public function test_it_renders_a_passing_check_with_an_ok_marker(): void
    {
        $commandTester = $this->commandTester(
            new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.'),
        );

        $commandTester->execute([]);

        self::assertStringContainsString('[OK] Composer: Available.', $commandTester->getDisplay());
    }

    public function test_it_renders_a_warning_check_as_a_warning_block(): void
    {
        $commandTester = $this->commandTester(
            new DoctorCheckResult('Composer', DoctorCheckStatus::Warning, 'Not found.'),
        );

        $commandTester->execute([]);

        $display = $commandTester->getDisplay();
        self::assertStringContainsString('[WARNING]', $display);
        self::assertStringContainsString('Composer: Not found.', $display);
    }

    public function test_it_renders_a_failing_check_as_an_error_block(): void
    {
        $commandTester = $this->commandTester(
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, 'Not installed.'),
        );

        $commandTester->execute([]);

        $display = $commandTester->getDisplay();
        self::assertStringContainsString('[ERROR]', $display);
        self::assertStringContainsString('Provider bridge: Not installed.', $display);
    }

    private function commandTester(DoctorCheckResult ...$results): CommandTester
    {
        $environmentDoctor = self::createStub(EnvironmentDoctorInterface::class);
        $environmentDoctor->method('diagnose')->willReturn($results);

        return new CommandTester(new DoctorCommand($environmentDoctor));
    }
}
