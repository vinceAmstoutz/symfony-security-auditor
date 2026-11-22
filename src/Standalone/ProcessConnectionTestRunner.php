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
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\SelfInvocation;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConnectionTestRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCommand;

/**
 * Starts this binary again as `doctor --check-connection`, so the request
 * goes through the provider bridge `init` has just installed.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProcessConnectionTestRunner implements ConnectionTestRunnerInterface
{
    public function __construct(
        private SelfInvocation $selfInvocation,
    ) {}

    #[Override]
    public function run(OutputInterface $output): bool
    {
        try {
            $binary = $this->selfInvocation->command();
        } catch (BridgeInstallationFailedException) {
            $output->writeln('The connection test could not start: this binary did not report its own path. Run "doctor --check-connection" yourself.');

            return false;
        }

        $process = new Process([...$binary, DoctorCommand::NAME, '--check-connection'], timeout: null);
        $process->run(static function (string $type, string $buffer) use ($output): void {
            $output->write($buffer);
        });

        return $process->isSuccessful();
    }
}
