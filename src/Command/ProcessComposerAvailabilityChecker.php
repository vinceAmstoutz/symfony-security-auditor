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
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Probes for a runnable `composer` by executing `composer --version` through
 * Symfony `Process` — the same subprocess-only convention the rest of the tool
 * uses (no raw shell, no argument-interpolation surface). The executable is
 * resolved through `ExecutableFinder` first: `Process` does not consult
 * `PATHEXT`, so a bare `composer` misses the `composer.bat`/`composer.cmd`
 * shims a Windows shell would find.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProcessComposerAvailabilityChecker implements ComposerAvailabilityCheckerInterface
{
    private const float PROCESS_TIMEOUT_SECONDS = 30.0;

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
            $composer = (new ExecutableFinder())->find('composer') ?? 'composer';
            $process = new Process([$composer, '--version']);
            $process->setTimeout(self::PROCESS_TIMEOUT_SECONDS);

            return $process;
        };
    }

    #[Override]
    public function isAvailable(): bool
    {
        $process = ($this->processBuilder)();

        try {
            $process->run();
        } catch (ExceptionInterface) {
            return false;
        }

        return $process->isSuccessful();
    }
}
