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
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;
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
 * way in and read back later: the command line if something throws, and
 * whether the run needs provider credentials when the audit command is built.
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

    private string $invocation = '';

    private bool $dryRun = false;

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
        $this->invocation = $input instanceof ArgvInput ? (string) $input : '';
        $this->dryRun = $input->hasParameterOption('--dry-run', true);

        if (!$this->completionRun($input)) {
            $this->consoleBanner->render($this->errorOutput($output));
        }

        return parent::doRun($input, $output);
    }

    /**
     * A `--dry-run` estimates cost from the scanned files and never reaches
     * the provider, so the standalone configuration does not have to resolve
     * a provider credential for it. Read here rather than from the command,
     * because the failure it prevents happens while that command is still
     * being built.
     */
    public function needsProviderCredentials(): bool
    {
        return !$this->dryRun;
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

    private function completionRun(InputInterface $input): bool
    {
        return \in_array($this->getCommandName($input), self::COMPLETION_COMMANDS, true);
    }

    private function errorOutput(OutputInterface $output): OutputInterface
    {
        return $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
    }
}
