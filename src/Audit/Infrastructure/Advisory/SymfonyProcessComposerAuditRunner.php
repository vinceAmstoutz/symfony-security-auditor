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

use Closure;
use Override;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;

use function Symfony\Component\String\u;

/**
 * Runs `composer audit --format=json --locked` via symfony/process. Composer's
 * exit code is non-zero whenever advisories are found, so we only treat a failure
 * as fatal when stdout is empty (the JSON is the contract).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyProcessComposerAuditRunner implements ComposerAuditRunnerInterface
{
    public const int DEFAULT_TIMEOUT_SECONDS = 60;

    /**
     * @param ?Closure(string): Process $processBuilder defaults to the standard composer-audit command; tests inject a stub
     */
    public function __construct(
        private int $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
        private ?Closure $processBuilder = null,
    ) {}

    /**
     * @return Closure(string): Process
     */
    public static function defaultProcessBuilder(): Closure
    {
        return static fn (string $path): Process => new Process(
            ['composer', 'audit', '--format=json', '--locked', '--no-interaction'],
            $path,
        );
    }

    #[Override]
    public function run(string $projectPath): string
    {
        $builder = $this->processBuilder ?? self::defaultProcessBuilder();
        $process = $builder($projectPath);

        try {
            $process->setTimeout((float) $this->timeoutSeconds);
            $process->run();
        } catch (ProcessTimedOutException $processTimedOutException) {
            throw AdvisorySourceUnavailableException::forTimeout($this->timeoutSeconds, $processTimedOutException);
        } catch (ExceptionInterface $exception) {
            throw AdvisorySourceUnavailableException::forProcessSetupFailure($exception);
        }

        $stdout = $process->getOutput();
        if (u($stdout)->trim()->isEmpty()) {
            $errorOutput = $process->getErrorOutput();

            throw AdvisorySourceUnavailableException::forFailedProcess($projectPath, '' !== $errorOutput ? $errorOutput : 'empty stdout', $process->isSuccessful() ? null : new ProcessFailedException($process));
        }

        return $stdout;
    }
}
