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
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ProcessComposerAvailabilityChecker;

final class ProcessComposerAvailabilityCheckerTest extends TestCase
{
    public function test_it_reports_composer_available_when_the_probe_succeeds(): void
    {
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['true']));

        self::assertTrue($processComposerAvailabilityChecker->isAvailable());
    }

    public function test_it_reports_composer_unavailable_when_the_probe_exits_non_zero(): void
    {
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['false']));

        self::assertFalse($processComposerAvailabilityChecker->isAvailable());
    }

    public function test_it_reports_composer_unavailable_when_the_probe_cannot_be_started(): void
    {
        $unlaunchableWorkingDirectory = sys_get_temp_dir().'/ssa-composer-missing-'.bin2hex(random_bytes(4));
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['true'], $unlaunchableWorkingDirectory));

        self::assertFalse($processComposerAvailabilityChecker->isAvailable());
    }

    public function test_default_process_builder_probes_the_composer_version_with_a_timeout(): void
    {
        $process = (ProcessComposerAvailabilityChecker::defaultProcessBuilder())();

        $commandLine = $process->getCommandLine();
        self::assertStringContainsString('composer', $commandLine);
        self::assertStringContainsString("'--version'", $commandLine);
        self::assertSame(30.0, $process->getTimeout());
    }
}
