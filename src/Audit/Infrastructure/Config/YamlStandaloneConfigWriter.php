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
     */
    #[Override]
    public function write(string $configFile, array $config): void
    {
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
}
