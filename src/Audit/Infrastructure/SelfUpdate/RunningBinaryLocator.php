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
 * Locates the running executable to replace. Only the self-contained standalone
 * binary (the phpmicro `micro` SAPI) may be replaced: under a normal PHP
 * interpreter `/proc/self/exe` resolves to the interpreter itself, so resolving
 * a path there and renaming a downloaded binary over it would destroy the
 * interpreter. When running as `micro`, the kernel exposes the binary at
 * `/proc/self/exe` (Linux); elsewhere (notably macOS, which has no
 * `/proc/self/exe`) it falls back to the resolved entry path, and — when the
 * binary was invoked by a bare name found on `PATH` so the entry path is not a
 * resolvable file — to a `PATH` lookup of that name. Both fallbacks accept only
 * an executable regular file, the way the shell resolves commands, so a
 * same-named stray file or directory is never mistaken for the running binary
 * and overwritten by an update.
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
