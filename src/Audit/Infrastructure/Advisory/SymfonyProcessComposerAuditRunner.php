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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\EmbeddedComposer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

use function Symfony\Component\String\u;

/**
 * Runs `composer audit --format=json --locked`. Fails only on an empty stdout:
 * composer exits non-zero whenever it finds an advisory.
 *
 * `--no-scripts` and `--no-plugins` keep the untrusted project's scripts and
 * `vendor/` plugins from running on the audit host.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SymfonyProcessComposerAuditRunner implements ComposerAuditRunnerInterface
{
    public const int DEFAULT_TIMEOUT_SECONDS = 60;

    private const array AUDIT_ARGUMENTS = ['audit', '--format=json', '--locked', '--no-interaction', '--no-scripts', '--no-plugins'];

    /**
     * @param ?Closure(string): Process $processBuilder defaults to {@see self::defaultProcessBuilder()}
     */
    public function __construct(
        private float $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
        private ?Closure $processBuilder = null,
    ) {}

    /**
     * @return Closure(string): Process
     */
    public static function defaultProcessBuilder(): Closure
    {
        return static fn (string $path): Process => new Process(['composer', ...self::AUDIT_ARGUMENTS], $path);
    }

    /**
     * Runs the bundled Composer, unpacked where `init` unpacks it, so the
     * audited directory holds none of it.
     *
     * @return Closure(string): Process the closure throws {@see AdvisorySourceUnavailableException} when the bundled Composer cannot be unpacked or no home directory resolves
     */
    public static function embeddedProcessBuilder(EmbeddedComposer $embeddedComposer, XdgConfigPathResolver $xdgConfigPathResolver): Closure
    {
        return static function (string $path) use ($embeddedComposer, $xdgConfigPathResolver): Process {
            try {
                $process = $embeddedComposer->process(\sprintf('%s/.composer', $xdgConfigPathResolver->dataDir()), self::AUDIT_ARGUMENTS);
            } catch (BridgeInstallationFailedException|UnresolvableConfigPathException $exception) {
                throw AdvisorySourceUnavailableException::forProcessSetupFailure($exception);
            }

            $process->setWorkingDirectory($path);

            return $process;
        };
    }

    #[Override]
    public function run(string $projectPath): string
    {
        $builder = $this->processBuilder ?? self::defaultProcessBuilder();
        $process = $builder($projectPath);
        $this->execute($process);

        $stdout = $process->getOutput();
        if (u($stdout)->trim()->isEmpty()) {
            throw $this->failureWithoutOutput($process, $projectPath);
        }

        return $stdout;
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    private function execute(Process $process): void
    {
        try {
            $process->setTimeout($this->timeoutSeconds);
            $process->run();
        } catch (ProcessTimedOutException $processTimedOutException) {
            throw AdvisorySourceUnavailableException::forTimeout($this->timeoutSeconds, $processTimedOutException);
        } catch (ExceptionInterface $exception) {
            throw AdvisorySourceUnavailableException::forProcessSetupFailure($exception);
        }
    }

    private function failureWithoutOutput(Process $process, string $projectPath): AdvisorySourceUnavailableException
    {
        if (127 === $process->getExitCode()) {
            return AdvisorySourceUnavailableException::forBinaryNotFound(new ProcessFailedException($process));
        }

        $errorOutput = $process->getErrorOutput();

        return AdvisorySourceUnavailableException::forFailedProcess($projectPath, '' !== $errorOutput ? $errorOutput : 'empty stdout', $process->isSuccessful() ? null : new ProcessFailedException($process));
    }
}
