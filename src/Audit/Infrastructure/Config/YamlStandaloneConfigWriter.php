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

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class YamlStandaloneConfigWriter implements StandaloneConfigWriterInterface
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public function write(string $configFile, array $config): void
    {
        $this->filesystem->dumpFile($configFile, Yaml::dump($config));
        $this->filesystem->chmod($configFile, 0o600);
    }
}
