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

namespace VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\SelfUpdate;

use Override;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;

/**
 * Locates the running executable to replace. Only the standalone binary (the
 * phpmicro `micro` SAPI) may be replaced: under a normal interpreter
 * `/proc/self/exe` resolves to the interpreter itself, and renaming a download
 * over it would destroy it. Under `micro`, Linux exposes the binary at
 * `/proc/self/exe`; elsewhere (macOS has none) it falls back to the resolved
 * entry path, then to a `PATH` lookup when the binary was invoked by bare name.
 * Both fallbacks accept only an executable regular file, as the shell resolves
 * commands, so a same-named stray file is never overwritten by an update.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
        $resolved = $this->executableFile(realpath($this->invokedScriptPath));
        if (null !== $resolved) {
            return $resolved;
        }

        return $this->resolvedFromPathEnvironment();
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
