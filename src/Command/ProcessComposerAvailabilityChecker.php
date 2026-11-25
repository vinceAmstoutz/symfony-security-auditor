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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Closure;
use Override;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\EmbeddedComposer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\TerminalText;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

use function Symfony\Component\String\b;
use function Symfony\Component\String\u;

/**
 * Probes for a runnable `composer` with `composer --version`, run through
 * `Process` without a shell. `Process` finds the Windows `composer.bat` and
 * `composer.cmd` shims through `PATHEXT`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProcessComposerAvailabilityChecker implements ComposerAvailabilityCheckerInterface
{
    private const float PROCESS_TIMEOUT_SECONDS = 30.0;

    private const int MAX_FAILURE_LENGTH = 200;

    /**
     * @param Closure(): Process $processBuilder the composer probe builder, self::defaultProcessBuilder() in production
     */
    public function __construct(
        private Closure $processBuilder,
    ) {}

    /**
     * @return Closure(): Process
     */
    public static function defaultProcessBuilder(): Closure
    {
        return static function (): Process {
            $process = new Process(['composer', '--version']);
            $process->setTimeout(self::PROCESS_TIMEOUT_SECONDS);

            return $process;
        };
    }

    /**
     * Probes the Composer this binary bundles, unpacked where `init` unpacks it.
     *
     * @return Closure(): Process the closure throws {@see BridgeInstallationFailedException} when that Composer cannot be unpacked and {@see UnresolvableConfigPathException} when no home directory resolves
     */
    public static function embeddedProcessBuilder(EmbeddedComposer $embeddedComposer, XdgConfigPathResolver $xdgConfigPathResolver): Closure
    {
        return static function () use ($embeddedComposer, $xdgConfigPathResolver): Process {
            $process = $embeddedComposer->process(\sprintf('%s/.composer', $xdgConfigPathResolver->dataDir()), ['--version']);
            $process->setTimeout(self::PROCESS_TIMEOUT_SECONDS);

            return $process;
        };
    }

    #[Override]
    public function probe(): ComposerProbe
    {
        try {
            $process = ($this->processBuilder)();
            $process->run();
        } catch (BridgeInstallationFailedException|ExceptionInterface|UnresolvableConfigPathException $exception) {
            return ComposerProbe::unavailable($this->printable($exception->getMessage()));
        }

        return $process->isSuccessful() ? ComposerProbe::available() : ComposerProbe::unavailable($this->failureOf($process));
    }

    private function failureOf(Process $process): string
    {
        $report = b($process->getErrorOutput())->trim();
        if ($report->isEmpty()) {
            $report = b($process->getOutput())->trim();
        }

        $exitCode = $process->getExitCode();
        \assert(null !== $exitCode, 'A process that has run has an exit code');

        return $report->isEmpty()
            ? \sprintf('"composer --version" exited with code %d', $exitCode)
            : $this->printable($report->toString());
    }

    private function printable(string $report): string
    {
        return u(TerminalText::escaped(b($report)->split("\n")[0]->trim()->toString()))->truncate(self::MAX_FAILURE_LENGTH, '…')->toString();
    }
}
