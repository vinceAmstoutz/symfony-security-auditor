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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Standalone;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplication;

final class StandaloneApplicationTest extends TestCase
{
    private const string WORDMARK = 'SECURITY AUDITOR';

    private const string SILENT_COMMAND = 'doctor';

    public function test_it_appends_the_models_dev_version_to_the_long_version(): void
    {
        self::assertSame(
            'symfony-security-auditor <info>1.2.3</info> (symfony/models-dev 132.0)',
            $this->application()->getLongVersion(),
        );
    }

    public function test_it_reports_the_configured_short_version(): void
    {
        self::assertSame('1.2.3', $this->application()->getVersion());
    }

    #[DataProvider('brandedInvocations')]
    public function test_it_announces_its_identity_before_the_command_runs(string $commandLine): void
    {
        self::assertStringContainsString(self::WORDMARK, $this->displayOf($commandLine));
    }

    /** @return iterable<string, array{string}> */
    public static function brandedInvocations(): iterable
    {
        yield 'the version flag, which never reaches a command' => ['--version'];
        yield 'the help flag on its own' => ['-h'];
        yield 'the long help flag on the audit command' => [\sprintf('%s --help', AuditCommand::NAME)];
        yield 'the short help flag on the audit command' => [\sprintf('%s -h', AuditCommand::ALIAS)];
        yield 'an ordinary command' => [self::SILENT_COMMAND];
    }

    #[DataProvider('unbrandedInvocations')]
    public function test_it_stays_silent_where_a_banner_would_be_noise(string $commandLine): void
    {
        self::assertStringNotContainsString(self::WORDMARK, $this->displayOf($commandLine));
    }

    /** @return iterable<string, array{string}> */
    public static function unbrandedInvocations(): iterable
    {
        yield 'the audit command, which prints its own banner' => [AuditCommand::NAME];
        yield 'the audit alias' => [AuditCommand::ALIAS];
        yield 'the audit command asked to treat -h as an argument' => [\sprintf('%s -- -h', AuditCommand::ALIAS)];
        yield 'the completion hook the shell runs on every TAB press' => ['_complete'];
        yield 'the completion script the shell evaluates' => ['completion'];
    }

    public function test_a_quiet_run_gets_no_banner(): void
    {
        $bufferedOutput = new BufferedOutput(OutputInterface::VERBOSITY_QUIET);

        $this->application()->doRun(new StringInput(self::SILENT_COMMAND), $bufferedOutput);

        self::assertStringNotContainsString(self::WORDMARK, $bufferedOutput->fetch());
    }

    public function test_the_banner_goes_to_the_error_output_so_it_never_pollutes_a_piped_stdout(): void
    {
        $errorOutput = new BufferedOutput();
        $consoleOutput = new ConsoleOutput();
        $consoleOutput->setErrorOutput($errorOutput);

        $this->application()->doRun(new StringInput(self::SILENT_COMMAND), $consoleOutput);

        self::assertStringContainsString(self::WORDMARK, $errorOutput->fetch());
    }

    private function displayOf(string $commandLine): string
    {
        $bufferedOutput = new BufferedOutput();

        $this->application()->doRun(new StringInput($commandLine), $bufferedOutput);

        return $bufferedOutput->fetch();
    }

    private function application(): StandaloneApplication
    {
        $standaloneApplication = new StandaloneApplication('symfony-security-auditor', '1.2.3', '132.0');
        $standaloneApplication->addCommand($this->silentCommand(AuditCommand::NAME, [AuditCommand::ALIAS]));
        $standaloneApplication->addCommand($this->silentCommand(self::SILENT_COMMAND));
        $standaloneApplication->addCommand($this->silentCommand('_complete'));
        $standaloneApplication->addCommand($this->silentCommand('completion'));

        return $standaloneApplication;
    }

    /** @param list<string> $aliases */
    private function silentCommand(string $name, array $aliases = []): Command
    {
        $command = new Command($name);
        $command->setAliases($aliases);
        $command->addArgument('path', InputArgument::OPTIONAL);
        $command->setCode(static fn (): int => Command::SUCCESS);

        return $command;
    }
}
