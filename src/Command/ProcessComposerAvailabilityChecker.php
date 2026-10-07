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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\TerminalText;

use function Symfony\Component\String\b;
use function Symfony\Component\String\u;

/**
 * Probes for a runnable `composer` by executing `composer --version` through
 * Symfony `Process` — the same subprocess-only convention the rest of the tool
 * uses (no raw shell, no argument-interpolation surface). A bare `composer`
 * argv[0] is sufficient on every platform: `Process` resolves it through its
 * own `ExecutableFinder`, which consults `PATHEXT` on Windows and so finds the
 * `composer.bat`/`composer.cmd` shims too.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProcessComposerAvailabilityChecker implements ComposerAvailabilityCheckerInterface
{
    private const float PROCESS_TIMEOUT_SECONDS = 30.0;

    private const int MAX_FAILURE_LENGTH = 200;

    /**
     * @param Closure(): Process $processBuilder the composer probe builder (use self::defaultProcessBuilder() in production); tests inject a stub
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

    #[Override]
    public function probe(): ComposerProbe
    {
        $process = ($this->processBuilder)();

        try {
            $process->run();
        } catch (ExceptionInterface $exception) {
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

        return $report->isEmpty()
            ? \sprintf('"composer --version" exited with code %d', $process->getExitCode())
            : $this->printable($report->toString());
    }

    private function printable(string $report): string
    {
        return u(TerminalText::escaped(b($report)->split("\n")[0]->trim()->toString()))->truncate(self::MAX_FAILURE_LENGTH, '…')->toString();
    }
}
