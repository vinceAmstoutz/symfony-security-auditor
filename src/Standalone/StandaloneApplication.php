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
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConsoleBanner;

/**
 * Extends the bare Symfony `Application` to append the bundled
 * `symfony/models-dev` pricing-catalog version to `--version`, and to put the
 * identity banner in front of every command rather than only `audit` — the
 * base class offers no other extension point for either. `--version` never
 * reaches a command at all, so an event listener could not cover it.
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

    public function __construct(
        string $name,
        string $version,
        private readonly string $modelsDevVersion,
        private readonly ConsoleBanner $consoleBanner = new ConsoleBanner(),
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
        if ($this->announcesIdentity($input)) {
            $this->consoleBanner->render($this->errorOutput($output));
        }

        return parent::doRun($input, $output);
    }

    /**
     * The banner goes to stderr so it never mixes into a machine-readable
     * stdout — `list --format=json`, `--version` piped into a version check.
     * `audit` is the one command that prints the banner itself, on the stream
     * its own `--format` dictates; asking for its help runs the `help`
     * command instead, which does not.
     */
    private function announcesIdentity(InputInterface $input): bool
    {
        if (\in_array($this->getCommandName($input), self::COMPLETION_COMMANDS, true)) {
            return false;
        }

        return $input->hasParameterOption(['--help', '-h'], true) || !$this->auditRequested($input);
    }

    private function auditRequested(InputInterface $input): bool
    {
        return \in_array($this->getCommandName($input), [AuditCommand::NAME, AuditCommand::ALIAS], true);
    }

    private function errorOutput(OutputInterface $output): OutputInterface
    {
        return $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
    }
}
