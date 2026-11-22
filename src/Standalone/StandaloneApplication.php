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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use Override;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\DumpCompletionCommand;
use Symfony\Component\Console\Exception\ExceptionInterface;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvironmentVariableName;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConsoleBanner;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConsoleBannerInterface;

/**
 * Appends the bundled `symfony/models-dev` pricing-catalog version to
 * `--version`, puts the identity banner in front of every command and echoes
 * the failing command line under a rendered error.
 *
 * Mutable by design: it captures the invocation on the way in and reads it
 * back later. See .claude/rules/php-classes.md for the opt-out policy.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class StandaloneApplication extends Application
{
    /**
     * Commands whose output the shell reads, which print no chrome on any stream.
     */
    private const array COMPLETION_COMMANDS = ['_complete', 'completion'];

    /**
     * Commands that describe other commands without running them.
     */
    private const array DESCRIBING_COMMANDS = ['help', 'list'];

    private const string COMPLETION_REQUEST = '_complete';

    /**
     * The option naming the variable a key is read from, whose value is masked
     * when echoed.
     */
    private const string VARIABLE_NAME_OPTION = '--env-var';

    private string $invocation = '';

    private bool $reachesNoProvider = false;

    private bool $describing = false;

    private ?InputInterface $input = null;

    public function __construct(
        string $name,
        string $version,
        private readonly string $modelsDevVersion,
        private readonly ConsoleBannerInterface $consoleBanner = new ConsoleBanner(),
    ) {
        parent::__construct($name, $version);
    }

    #[Override]
    protected function getDefaultCommands(): array
    {
        return array_map(
            static fn (Command $command): Command => $command instanceof DumpCompletionCommand ? $command->setHidden() : $command,
            parent::getDefaultCommands(),
        );
    }

    #[Override]
    public function getLongVersion(): string
    {
        return \sprintf('%s (symfony/models-dev %s)', parent::getLongVersion(), $this->modelsDevVersion);
    }

    #[Override]
    public function doRun(InputInterface $input, OutputInterface $output): int
    {
        $this->input = $input;
        $this->invocation = $input instanceof ArgvInput ? $this->echoable($input) : '';
        $this->reachesNoProvider = $input->hasParameterOption(['--dry-run', '--show-scanned'], true);
        $this->describing = $input->hasParameterOption(['--help', '-h'], true) || $this->namesADescribingCommand($this->getCommandName($input));

        if (!$this->completionRun($input)) {
            $this->consoleBanner->render($this->errorOutput($output));
        }

        return parent::doRun($input, $output);
    }

    private function namesADescribingCommand(?string $name): bool
    {
        return null === $name || self::COMPLETION_REQUEST === $name || $this->abbreviatesADescribingCommand(strtolower($name));
    }

    /**
     * Matches an abbreviation of `help` or `list` case-insensitively, as the
     * base class does, without building a command from the configuration.
     */
    private function abbreviatesADescribingCommand(string $name): bool
    {
        foreach (self::DESCRIBING_COMMANDS as $describingCommand) {
            if (str_starts_with($describingCommand, $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * False for a `--dry-run` or a `--show-scanned` run, neither of which
     * reaches the provider.
     */
    public function needsProviderCredentials(): bool
    {
        return !$this->reachesNoProvider;
    }

    /**
     * Returns the `project-path` the command line gives the audit, read before
     * the command is built, or null when none is given or the line does not
     * bind.
     */
    public function projectPathGivenTo(Command $command): ?string
    {
        $projectPath = $this->inputBoundTo($command)?->getArgument('project-path');

        return \is_string($projectPath) && '' !== trim($projectPath) ? $projectPath : null;
    }

    /**
     * Returns the `--path` values the command line gives the audit command,
     * read before the command is built.
     *
     * @return list<string>
     */
    public function scanPathsGivenTo(Command $command): array
    {
        $scanPaths = [];
        foreach ((array) $this->inputBoundTo($command)?->getOption('path') as $scanPath) {
            if (\is_string($scanPath)) {
                $scanPaths[] = $scanPath;
            }
        }

        return $scanPaths;
    }

    private function inputBoundTo(Command $command): ?InputInterface
    {
        if (!$this->input instanceof InputInterface) {
            return null;
        }

        $input = clone $this->input;

        try {
            $input->bind($this->definitionWithApplicationOf($command));
        } catch (ExceptionInterface) {
            return null;
        }

        return $input;
    }

    private function definitionWithApplicationOf(Command $command): InputDefinition
    {
        $inputDefinition = $this->getDefinition();
        $commandDefinition = $command->getNativeDefinition();

        return new InputDefinition([
            ...$inputDefinition->getArguments(),
            ...$commandDefinition->getArguments(),
            ...$inputDefinition->getOptions(),
            ...$commandDefinition->getOptions(),
        ]);
    }

    /**
     * True for help, a listing or shell completion, which describe a command
     * from its class instead of building it from the configuration.
     */
    public function describesCommandsOnly(): bool
    {
        return $this->describing;
    }

    /**
     * Echoes the command line under the error block, unless the input is a
     * programmatic `ArrayInput`.
     */
    #[Override]
    public function renderThrowable(Throwable $throwable, OutputInterface $output): void
    {
        parent::renderThrowable($throwable, $output);

        if ('' === $this->invocation) {
            return;
        }

        $output->writeln(
            \sprintf(' <comment>Command:</comment> %s %s', $this->getName(), OutputFormatter::escape($this->invocation)),
            OutputInterface::VERBOSITY_QUIET,
        );
    }

    /**
     * Returns the command line to echo under an error, masking a key pasted as
     * the `--env-var` value so it never reaches a terminal or a CI log.
     */
    private function echoable(ArgvInput $argvInput): string
    {
        $variableName = $argvInput->getParameterOption(self::VARIABLE_NAME_OPTION);
        if (!\is_string($variableName)) {
            return (string) $argvInput;
        }

        $shown = EnvironmentVariableName::shown($variableName);

        return (string) new ArgvInput(['', ...array_map(
            static fn (string $token): string => str_replace($variableName, $shown, $token),
            $argvInput->getRawTokens(),
        )]);
    }

    private function completionRun(InputInterface $input): bool
    {
        return \in_array($this->getCommandName($input), self::COMPLETION_COMMANDS, true);
    }

    private function errorOutput(OutputInterface $output): OutputInterface
    {
        return $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
    }
}
