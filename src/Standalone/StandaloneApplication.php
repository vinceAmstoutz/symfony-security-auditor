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
 * Extends the bare Symfony `Application` to append the bundled
 * `symfony/models-dev` pricing-catalog version to `--version`, to put the
 * identity banner in front of every command, and to echo the failing command
 * line under a rendered error — the base class offers no extension point for
 * any of the three. `--version` never reaches a command at all, so an event
 * listener could not cover it.
 *
 * Mutable by design — non-readonly because the invocation is captured on the
 * way in and read back later: the command line if something throws, whether
 * the run needs provider credentials when the audit command is built, whether
 * it only describes the commands it would build, and which project it names.
 * See .claude/rules/php-classes.md for the opt-out policy.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class StandaloneApplication extends Application
{
    /**
     * `_complete` runs on every TAB press and `completion` emits a script the
     * shell evaluates, so neither may print chrome on any stream.
     */
    private const array COMPLETION_COMMANDS = ['_complete', 'completion'];

    /**
     * Commands that read other commands' definitions without running them,
     * matched the way the base class resolves an abbreviation. Running with
     * no command name runs `list`, and shell completion reads definitions
     * too.
     */
    private const array DESCRIBING_COMMANDS = ['help', 'list'];

    private const string COMPLETION_REQUEST = '_complete';

    /**
     * The option naming the variable a key is read from, where a key pasted
     * by mistake would otherwise be echoed back.
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
     * The base class runs `hel audit` as `help audit`, matching an abbreviation
     * case-insensitively when nothing else does, and no other command starts
     * like `help` or `list`. Matching the prefix here, rather than through
     * `find()`, keeps the lookup from building a command out of the
     * configuration before this flag is set.
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
     * A `--dry-run` estimates cost from the scanned files and `--show-scanned`
     * lists them, and neither reaches the provider, so the standalone
     * configuration does not have to resolve a provider credential for them.
     * Read here rather than from the command, because the failure it
     * prevents happens while that command is still being built.
     */
    public function needsProviderCredentials(): bool
    {
        return !$this->reachesNoProvider;
    }

    /**
     * The `project-path` the command line gives the audit, read by binding a
     * copy of it to the command's own definition — the only way to tell that
     * argument from the value of an option — before the command is built from
     * the configuration, which is where the audited project's own file has to
     * be chosen. Null when none is given or the line does not bind, which the
     * command itself then reports.
     */
    public function projectPathGivenTo(Command $command): ?string
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

        $projectPath = $input->getArgument('project-path');

        return \is_string($projectPath) && '' !== trim($projectPath) ? $projectPath : null;
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
     * Help, a listing and shell completion only describe commands, so a
     * command built from the configuration can be described from its class
     * instead — before `init` has written a configuration, or with one that
     * would not boot. Mirrors the `--help` detection of the base class.
     */
    public function describesCommandsOnly(): bool
    {
        return $this->describing;
    }

    /**
     * The error block alone does not say what produced it, which is what a
     * pasted CI log or bug report is missing. Only a real command line is
     * echoed — a programmatic `ArrayInput` has no invocation to reproduce.
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
     * The command line as it is echoed under an error, with the value of
     * `--env-var` shown the way a refused variable name is: a key pasted
     * there instead of its variable's name is masked, never printed into a
     * terminal or a CI log.
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
