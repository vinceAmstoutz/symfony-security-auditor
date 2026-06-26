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

    public function configFile(): string
    {
        return $this->baseDirectory($this->xdgConfigHome, '.config').'/'.self::APP_DIRECTORY.'/'.self::CONFIG_FILENAME;
    }

    public function cacheDir(): string
    {
        return $this->baseDirectory($this->xdgCacheHome, '.cache').'/'.self::APP_DIRECTORY;
    }

    public function dataDir(): string
    {
        return $this->baseDirectory($this->xdgDataHome, '.local/share').'/'.self::APP_DIRECTORY;
    }

    private function baseDirectory(?string $xdgBase, string $homeRelativeFallback): string
    {
        if (null !== $xdgBase && '' !== $xdgBase) {
            return $xdgBase;
        }

        if (null !== $this->home && '' !== $this->home) {
            return $this->home.'/'.$homeRelativeFallback;
        }

        throw UnresolvableConfigPathException::missingHome();
    }
}
