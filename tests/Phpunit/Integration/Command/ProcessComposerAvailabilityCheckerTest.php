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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ComposerProbe;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ProcessComposerAvailabilityChecker;

final class ProcessComposerAvailabilityCheckerTest extends TestCase
{
    public function test_it_reports_composer_available_when_the_probe_succeeds(): void
    {
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['true']));

        self::assertEquals(ComposerProbe::available(), $processComposerAvailabilityChecker->probe());
    }

    public function test_it_reports_why_composer_is_unavailable_when_the_probe_exits_non_zero(): void
    {
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['sh', '-c', 'echo "php: not found" >&2; exit 127']));

        self::assertEquals(ComposerProbe::unavailable('php: not found'), $processComposerAvailabilityChecker->probe());
    }

    #[DataProvider('unavailableProbeOutputs')]
    public function test_it_reports_the_first_line_the_probe_printed_as_the_reason(string $script, string $expectedFailure): void
    {
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['sh', '-c', $script]));

        self::assertEquals(ComposerProbe::unavailable($expectedFailure), $processComposerAvailabilityChecker->probe());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unavailableProbeOutputs(): iterable
    {
        yield 'a Windows shell error, closed by a carriage return' => ["printf '%s\\r\\n%s\\r\\n' \"'composer' is not recognized as an internal or external command,\" 'operable program or batch file.' >&2; exit 1", "'composer' is not recognized as an internal or external command,"];
        yield 'what it printed on standard output when it printed nothing on standard error' => ['echo "composer is broken"; exit 1', 'composer is broken'];
        yield 'standard error before standard output' => ['echo "from stdout"; echo "from stderr" >&2; exit 1', 'from stderr'];
        yield 'blank lines before the message' => ["printf '\\n\\n  spaced out  \\n' >&2; exit 1", 'spaced out'];
        yield 'text that is not UTF-8, as a Windows console in another language prints it' => ["printf '\\351chec' >&2; exit 1", '\\351chec'];
        yield 'nothing at all' => ['exit 3', '"composer --version" exited with code 3'];
    }

    public function test_it_escapes_the_control_characters_of_the_reason(): void
    {
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['sh', '-c', "printf 'bad \\033[31mred' >&2; exit 1"]));

        self::assertEquals(ComposerProbe::unavailable('bad \\033[31mred'), $processComposerAvailabilityChecker->probe());
    }

    public function test_it_cuts_a_reason_longer_than_two_hundred_characters(): void
    {
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['sh', '-c', 'printf "%0300d" 0 >&2; exit 1']));

        self::assertEquals(ComposerProbe::unavailable(str_repeat('0', 199).'…'), $processComposerAvailabilityChecker->probe());
    }

    public function test_it_reports_why_composer_is_unavailable_when_the_probe_cannot_be_started(): void
    {
        $unlaunchableWorkingDirectory = sys_get_temp_dir().'/ssa-composer-missing-'.bin2hex(random_bytes(4));
        $processComposerAvailabilityChecker = new ProcessComposerAvailabilityChecker(static fn (): Process => new Process(['true'], $unlaunchableWorkingDirectory));

        $composerProbe = $processComposerAvailabilityChecker->probe();

        self::assertFalse($composerProbe->isAvailable);
        self::assertStringContainsString($unlaunchableWorkingDirectory, $composerProbe->failure);
    }

    public function test_default_process_builder_probes_the_composer_version_with_a_timeout(): void
    {
        $process = (ProcessComposerAvailabilityChecker::defaultProcessBuilder())();

        $commandLine = $process->getCommandLine();
        self::assertStringContainsString("'composer'", $commandLine);
        self::assertStringContainsString("'--version'", $commandLine);
        self::assertSame(30.0, $process->getTimeout());
    }
}
