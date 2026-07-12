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
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class XdgConfigPathResolver
{
    private const string APP_DIRECTORY = 'symfony-security-auditor';

    private const string CONFIG_FILENAME = 'config.yaml';

    public function __construct(
        private ?string $xdgConfigHome,
        private ?string $xdgCacheHome,
        private ?string $home,
        private ?string $xdgDataHome = null,
    ) {}

    /**
     * XDG variables always win; on Windows the base directories fall back to the
     * native `%APPDATA%` (config) and `%LOCALAPPDATA%` (cache/data) locations,
     * with `%USERPROFILE%` as the home, since Windows has no `$HOME`/XDG dirs.
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
     * The XDG Base Directory Specification requires every one of these
     * variables to hold an absolute path and says implementations "may
     * consider" a relative value invalid — this treats it as unset (falling
     * back to `$home`) rather than resolving paths relative to whatever the
     * process's current working directory happens to be, e.g. an audited
     * project directory the standalone binary is invoked from.
     *
     * @throws UnresolvableConfigPathException
     */
    private function baseDirectory(?string $xdgBase, string $homeRelativeFallback): string
    {
        if (null !== $xdgBase && '' !== $xdgBase && $this->isAbsolutePath($xdgBase)) {
            return $xdgBase;
        }

        if (null !== $this->home && '' !== $this->home) {
            return \sprintf('%s/%s', $this->home, $homeRelativeFallback);
        }

        throw UnresolvableConfigPathException::missingHome();
    }

    /**
     * `Symfony\Component\Filesystem\Path::isAbsolute()` only recognizes a
     * Windows drive-letter path (`C:\...`/`C:/...`) as absolute when the
     * *current* runtime's `DIRECTORY_SEPARATOR` is itself `\` — but
     * {@see self::fromEnvironment()} deliberately builds a Windows-shaped
     * instance from a `Windows` `$osFamily` argument regardless of the OS
     * actually running the process (see the Windows-environment test suite),
     * so an OS-runtime-dependent check would wrongly reject a genuine
     * absolute `%APPDATA%`-derived path on a non-Windows CI runner.
     */
    private function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/')
            || str_starts_with($path, '\\')
            || 1 === preg_match('#^[A-Za-z]:[/\\\\]#', $path);
    }
}
