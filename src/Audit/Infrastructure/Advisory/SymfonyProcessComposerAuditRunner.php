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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;

/**
 * Runs `composer audit --format=json --locked` via symfony/process. Composer's
 * exit code is non-zero whenever advisories are found, so we only treat a failure
 * as fatal when stdout is empty (the JSON is the contract).
 */
final readonly class SymfonyProcessComposerAuditRunner implements ComposerAuditRunnerInterface
{
    public const int DEFAULT_TIMEOUT_SECONDS = 60;

    public function __construct(
        private int $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
    ) {}

    public function run(string $projectPath): string
    {
        $process = new Process(
            ['composer', 'audit', '--format=json', '--locked', '--no-interaction'],
            $projectPath,
        );
        $process->setTimeout((float) $this->timeoutSeconds);

        try {
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw AdvisorySourceUnavailableException::forBinaryNotFound($exception);
        }

        $stdout = $process->getOutput();
        if ('' === trim($stdout)) {
            throw AdvisorySourceUnavailableException::forFailedProcess($projectPath, $process->getErrorOutput() ?: 'empty stdout', new ProcessFailedException($process));
        }

        return $stdout;
    }
}
