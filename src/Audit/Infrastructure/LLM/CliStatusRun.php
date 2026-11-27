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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\Component\Process\Exception\ExceptionInterface as ProcessExceptionInterface;
use Symfony\Component\Process\Process;

/**
 * Runs a CLI's status command in the environment the audit runs the CLI in,
 * without the variables the audit keeps from it, from a fresh
 * CliAgentWorkingDirectory unless told where, so the settings of the
 * current directory never apply.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CliStatusRun
{
    public function __construct(
        private float $timeoutSeconds = 20.0,
    ) {}

    /**
     * Returns null when the command does not finish in time.
     *
     * @param list<string>          $command
     * @param list<string>          $removedVariables the variables the audit keeps from the CLI, kept from the command too
     * @param array<string, string> $environment      variables the command runs with besides
     */
    public function run(array $command, array $removedVariables, array $environment = [], ?string $workingDirectory = null): ?Process
    {
        $privateDirectory = null === $workingDirectory ? new CliAgentWorkingDirectory() : null;
        $process = new Process($command, $workingDirectory ?? $privateDirectory?->path, [...array_fill_keys($removedVariables, false), ...$environment], timeout: $this->timeoutSeconds);

        try {
            $process->run();
        } catch (ProcessExceptionInterface) {
            return null;
        }

        return $process;
    }
}
