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
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
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

    private const string FAILING_COMMAND = 'boom';

    private const string FAILURE_MESSAGE = 'the audit could not start';

    private const string PASTED_KEY = 'AbCdEfGhIjKlMnOpQrStUvWxYz012345';

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

    #[DataProvider('everyInvocation')]
    public function test_it_announces_its_identity_before_the_command_runs(string $commandLine): void
    {
        self::assertStringContainsString(self::WORDMARK, $this->displayOf($commandLine));
    }

    /** @return iterable<string, array{string}> */
    public static function everyInvocation(): iterable
    {
        yield 'the version flag, which never reaches a command' => ['--version'];
        yield 'the help flag on its own' => ['-h'];
        yield 'the audit command' => [AuditCommand::NAME];
        yield 'the audit alias' => [AuditCommand::ALIAS];
        yield 'help for the audit command' => [\sprintf('%s --help', AuditCommand::ALIAS)];
        yield 'an ordinary command' => [self::SILENT_COMMAND];
    }

    #[DataProvider('completionInvocations')]
    public function test_it_stays_silent_for_the_completion_commands(string $commandLine): void
    {
        self::assertStringNotContainsString(self::WORDMARK, $this->displayOf($commandLine));
    }

    /** @return iterable<string, array{string}> */
    public static function completionInvocations(): iterable
    {
        yield 'the hook the shell runs on every TAB press' => ['_complete'];
        yield 'the script the shell evaluates' => ['completion'];
    }

    public function test_a_quiet_run_gets_no_banner(): void
    {
        $bufferedOutput = new BufferedOutput(OutputInterface::VERBOSITY_QUIET);

        $this->application()->doRun(new StringInput(self::SILENT_COMMAND), $bufferedOutput);

        self::assertStringNotContainsString(self::WORDMARK, $bufferedOutput->fetch());
    }

    public function test_the_banner_goes_to_the_error_output_so_it_never_pollutes_a_piped_stdout(): void
    {
        $bufferedOutput = new BufferedOutput();
        $consoleOutput = new ConsoleOutput();
        $consoleOutput->setErrorOutput($bufferedOutput);

        $this->application()->doRun(new StringInput(self::SILENT_COMMAND), $consoleOutput);

        self::assertStringContainsString(self::WORDMARK, $bufferedOutput->fetch());
    }

    public function test_it_echoes_the_failing_command_line_under_the_rendered_error(): void
    {
        self::assertStringContainsString(
            \sprintf(' Command: symfony-security-auditor %s', self::FAILING_COMMAND),
            $this->displayOfFailure(new StringInput(self::FAILING_COMMAND)),
        );
    }

    public function test_the_echoed_command_line_follows_the_error_block_rather_than_replacing_it(): void
    {
        self::assertMatchesRegularExpression(
            \sprintf('/%s.*Command: symfony-security-auditor %s/s', preg_quote(self::FAILURE_MESSAGE, '/'), self::FAILING_COMMAND),
            $this->displayOfFailure(new StringInput(self::FAILING_COMMAND)),
        );
    }

    public function test_the_echoed_command_line_cannot_smuggle_console_markup(): void
    {
        $display = $this->displayOfFailure(new StringInput(\sprintf('%s "<comment>oops</comment>"', self::FAILING_COMMAND)));

        self::assertStringContainsString("'<comment>oops</comment>'", $display);
    }

    #[DataProvider('variableNameOptions')]
    public function test_the_echoed_command_line_masks_a_key_pasted_where_a_variable_name_belongs(string $option, string $echoed): void
    {
        $display = $this->displayOfFailure(new StringInput(\sprintf('%s %s', self::FAILING_COMMAND, \sprintf($option, self::PASTED_KEY))));

        self::assertSame(
            [false, true],
            [str_contains($display, self::PASTED_KEY), str_contains($display, \sprintf('Command: symfony-security-auditor %s %s', self::FAILING_COMMAND, $echoed))],
            $display,
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function variableNameOptions(): iterable
    {
        yield 'given with an equals sign' => ['--env-var=%s', "--env-var='AbCdEf…2345'"];
        yield 'given as the next word' => ['--env-var %s', "--env-var 'AbCdEf…2345'"];
        yield 'typed past the end of the options' => ['-- --env-var=%s', "-- --env-var='AbCdEf…2345'"];
    }

    public function test_the_echoed_command_line_keeps_a_variable_name_as_typed(): void
    {
        self::assertStringContainsString(
            \sprintf('Command: symfony-security-auditor %s --env-var=GATEWAY_TOKEN', self::FAILING_COMMAND),
            $this->displayOfFailure(new StringInput(\sprintf('%s --env-var=GATEWAY_TOKEN', self::FAILING_COMMAND))),
        );
    }

    public function test_a_programmatic_invocation_has_no_command_line_to_echo(): void
    {
        $display = $this->displayOfFailure(new ArrayInput(['command' => self::FAILING_COMMAND]));

        self::assertStringNotContainsString('Command:', $display);
    }

    #[DataProvider('credentialRequirements')]
    public function test_only_a_run_that_never_reaches_the_provider_may_skip_its_credential(string $commandLine, bool $expected): void
    {
        $standaloneApplication = $this->application();
        $standaloneApplication->doRun(new StringInput($commandLine), new BufferedOutput());

        self::assertSame($expected, $standaloneApplication->needsProviderCredentials());
    }

    /** @return iterable<string, array{string, bool}> */
    public static function credentialRequirements(): iterable
    {
        yield 'a dry run never reaches the provider' => [\sprintf('%s --dry-run', AuditCommand::ALIAS), false];
        yield 'nor does a listing of the scanned files' => [\sprintf('%s --show-scanned', AuditCommand::ALIAS), false];
        yield 'nor a listing that prices them too' => [\sprintf('%s --show-scanned --dry-run', AuditCommand::ALIAS), false];
        yield 'a real audit does' => [AuditCommand::ALIAS, true];
        yield 'so does one whose path merely looks like the flag' => [\sprintf('%s -- --dry-run', AuditCommand::ALIAS), true];
        yield 'or like the listing flag' => [\sprintf('%s -- --show-scanned', AuditCommand::ALIAS), true];
        yield 'and so does any other command' => [self::SILENT_COMMAND, true];
    }

    private function displayOfFailure(InputInterface $input): string
    {
        $bufferedOutput = new BufferedOutput();
        $standaloneApplication = $this->application();
        $standaloneApplication->setAutoExit(false);

        $standaloneApplication->run($input, $bufferedOutput);

        return $bufferedOutput->fetch();
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
        $standaloneApplication->addCommand($this->failingCommand());

        return $standaloneApplication;
    }

    private function failingCommand(): Command
    {
        $command = new Command(self::FAILING_COMMAND);
        $command->addArgument('path', InputArgument::OPTIONAL);
        $command->addOption('env-var', null, InputOption::VALUE_REQUIRED);
        $command->setCode(static fn (): int => throw new RuntimeException(self::FAILURE_MESSAGE));

        return $command;
    }

    /** @param list<string> $aliases */
    private function silentCommand(string $name, array $aliases = []): Command
    {
        $command = new Command($name);
        $command->setAliases($aliases);
        $command->addArgument('path', InputArgument::OPTIONAL);
        $command->addOption('dry-run', null, InputOption::VALUE_NONE);
        $command->addOption('show-scanned', null, InputOption::VALUE_NONE);
        $command->setCode(static fn (): int => Command::SUCCESS);

        return $command;
    }
}
