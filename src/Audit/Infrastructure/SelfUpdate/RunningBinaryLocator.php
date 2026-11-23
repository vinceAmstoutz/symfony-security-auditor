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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;

/**
 * Locates the running standalone binary to replace. Refuses any SAPI but
 * phpmicro's `micro`: elsewhere `/proc/self/exe` is the PHP interpreter.
 * Without `/proc/self/exe`, resolves the entry path as a shell resolves a
 * command: a bare name only on `PATH`, never in the working directory.
 * Accepts only an executable regular file.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class RunningBinaryLocator implements RunningBinaryLocatorInterface
{
    private const string STANDALONE_SAPI = 'micro';

    public function __construct(
        private string $procSelfExePath = '/proc/self/exe',
        private string $invokedScriptPath = '',
        private string $sapi = \PHP_SAPI,
        private string $pathEnvironment = '',
    ) {}

    /**
     * @throws SelfUpdateFailedException
     */
    #[Override]
    public function path(): string
    {
        if (self::STANDALONE_SAPI !== $this->sapi) {
            throw SelfUpdateFailedException::forNonStandaloneRuntime($this->sapi);
        }

        return $this->kernelReportedPath()
            ?? $this->resolvedEntryPath()
            ?? throw SelfUpdateFailedException::forUndeterminedBinaryPath();
    }

    private function kernelReportedPath(): ?string
    {
        if (!is_link($this->procSelfExePath)) {
            return null;
        }

        $resolved = readlink($this->procSelfExePath);

        return \is_string($resolved) ? $resolved : null;
    }

    private function resolvedEntryPath(): ?string
    {
        return $this->isBareName()
            ? $this->resolvedFromPathEnvironment()
            : $this->executableFile(realpath($this->invokedScriptPath));
    }

    private function isBareName(): bool
    {
        return !str_contains($this->invokedScriptPath, \DIRECTORY_SEPARATOR);
    }

    private function resolvedFromPathEnvironment(): ?string
    {
        foreach (explode(\PATH_SEPARATOR, $this->pathEnvironment) as $directory) {
            if ('' === $directory) {
                continue;
            }

            $candidate = $this->executableFile(realpath($directory.\DIRECTORY_SEPARATOR.$this->invokedScriptPath));
            if (null !== $candidate) {
                return $candidate;
            }
        }

        return null;
    }

    private function executableFile(false|string $path): ?string
    {
        return \is_string($path) && is_file($path) && is_executable($path) ? $path : null;
    }
}
