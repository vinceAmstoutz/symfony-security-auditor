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

use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\StandaloneConfigWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsafeStandaloneConfigWriteException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class YamlStandaloneConfigWriter implements StandaloneConfigWriterInterface
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    #[Override]
    public function write(string $configFile, array $config): void
    {
        $this->assertSafeToWrite($configFile);

        try {
            if (!$this->filesystem->exists($configFile)) {
                $this->filesystem->mkdir(\dirname($configFile));
                $this->filesystem->touch($configFile);
                $this->filesystem->chmod($configFile, 0o600);
            }

            $this->filesystem->dumpFile($configFile, Yaml::dump($config));
            $this->filesystem->chmod($configFile, 0o600);
        } catch (IOException $ioException) {
            throw StandaloneConfigWriteException::fromIOException($configFile, $ioException);
        }
    }

    /**
     * `Filesystem::dumpFile()` transparently writes through a pre-existing
     * symlink at its destination, and `Filesystem::mkdir()` treats a
     * symlinked directory as already existing — mirrors the same guard
     * already applied to the filesystem attacker/reviewer caches and the
     * advisory cache.
     *
     * @throws UnsafeStandaloneConfigWriteException
     */
    private function assertSafeToWrite(string $path): void
    {
        if (is_link($path) || is_link(\dirname($path))) {
            throw UnsafeStandaloneConfigWriteException::forSymlinkedPath($path);
        }
    }
}
