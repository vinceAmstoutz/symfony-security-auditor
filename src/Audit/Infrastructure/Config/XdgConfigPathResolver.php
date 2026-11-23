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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class XdgConfigPathResolver
{
    private const string APP_DIRECTORY = 'symfony-security-auditor';

    private const string CONFIG_FILENAME = 'config.yaml';

    private const string CREDENTIALS_FILENAME = 'credentials.json';

    public const string HOME_OVERRIDE_VARIABLE = 'SYMFONY_SECURITY_AUDITOR_HOME';

    public function __construct(
        private ?string $xdgConfigHome,
        private ?string $xdgCacheHome,
        private ?string $home,
        private ?string $xdgDataHome = null,
        private ?string $applicationHome = null,
    ) {}

    /**
     * `SYMFONY_SECURITY_AUDITOR_HOME` outranks the XDG variables, which outrank
     * `$HOME`. On Windows, `%APPDATA%` and `%LOCALAPPDATA%` stand in for the
     * XDG variables and `%USERPROFILE%` for `$HOME`.
     *
     * @param array<string, string> $environment
     */
    public static function fromEnvironment(array $environment, string $osFamily): self
    {
        $windows = 'Windows' === $osFamily;

        return new self(
            $environment['XDG_CONFIG_HOME'] ?? ($windows ? ($environment['APPDATA'] ?? null) : null),
            $environment['XDG_CACHE_HOME'] ?? ($windows ? ($environment['LOCALAPPDATA'] ?? null) : null),
            $environment['HOME'] ?? ($windows ? ($environment['USERPROFILE'] ?? null) : null),
            $environment['XDG_DATA_HOME'] ?? ($windows ? ($environment['LOCALAPPDATA'] ?? null) : null),
            $environment[self::HOME_OVERRIDE_VARIABLE] ?? null,
        );
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function configFile(): string
    {
        return \sprintf('%s/%s/%s', $this->baseDirectory($this->xdgConfigHome, '.config'), self::APP_DIRECTORY, self::CONFIG_FILENAME);
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function credentialsFile(): string
    {
        return \sprintf('%s/%s/%s', $this->baseDirectory($this->xdgConfigHome, '.config'), self::APP_DIRECTORY, self::CREDENTIALS_FILENAME);
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function cacheDir(): string
    {
        return \sprintf('%s/%s', $this->baseDirectory($this->xdgCacheHome, '.cache'), self::APP_DIRECTORY);
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function dataDir(): string
    {
        return \sprintf('%s/%s', $this->baseDirectory($this->xdgDataHome, '.local/share'), self::APP_DIRECTORY);
    }

    /**
     * Treats a relative XDG variable as unset, never resolving it against the
     * working directory, which may be the audited project.
     *
     * @throws UnresolvableConfigPathException
     */
    private function baseDirectory(?string $xdgBase, string $homeRelativeFallback): string
    {
        return $this->applicationHomeBase($homeRelativeFallback)
            ?? $this->absoluteBase($xdgBase)
            ?? $this->osHomeBase($homeRelativeFallback)
            ?? throw UnresolvableConfigPathException::missingHome();
    }

    /**
     * Returns why the `SYMFONY_SECURITY_AUDITOR_HOME` override cannot be used,
     * or null when it can or is not set.
     */
    public function applicationHomeRefusal(): ?string
    {
        try {
            $this->applicationHomeBase('');
        } catch (UnresolvableConfigPathException $unresolvableConfigPathException) {
            return $unresolvableConfigPathException->getMessage();
        }

        return null;
    }

    /**
     * Refuses a relative override rather than skipping it, unlike a relative
     * `$HOME` or XDG variable.
     *
     * @throws UnresolvableConfigPathException
     */
    private function applicationHomeBase(string $homeRelativeFallback): ?string
    {
        if (null === $this->applicationHome || '' === $this->applicationHome) {
            return null;
        }

        if (!$this->isAbsolutePath($this->applicationHome)) {
            throw UnresolvableConfigPathException::relativeApplicationHome(self::HOME_OVERRIDE_VARIABLE, $this->applicationHome);
        }

        return \sprintf('%s/%s', $this->applicationHome, $homeRelativeFallback);
    }

    /**
     * Ignores a relative `$HOME`, which would put the config, the credentials
     * and the cache inside the audited project.
     */
    private function osHomeBase(string $homeRelativeFallback): ?string
    {
        $home = $this->absoluteBase($this->home);

        return null !== $home ? \sprintf('%s/%s', $home, $homeRelativeFallback) : null;
    }

    private function absoluteBase(?string $path): ?string
    {
        return null !== $path && '' !== $path && $this->isAbsolutePath($path) ? $path : null;
    }

    /**
     * Recognizes a Windows drive path on every OS, unlike `Path::isAbsolute()`:
     * {@see self::fromEnvironment()} builds a Windows instance anywhere.
     */
    private function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/')
            || str_starts_with($path, '\\')
            || 1 === preg_match('#^[A-Za-z]:[/\\\\]#', $path);
    }
}
