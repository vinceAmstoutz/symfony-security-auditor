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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\StandaloneConfigWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsafeStandaloneConfigWriteException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class YamlStandaloneConfigWriter implements StandaloneConfigWriterInterface
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
        private StandaloneConfigFileReader $standaloneConfigFileReader = new StandaloneConfigFileReader(),
        private ProviderBoundSettings $providerBoundSettings = new ProviderBoundSettings(),
    ) {}

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    #[Override]
    public function write(string $configFile, array $config): array
    {
        $this->assertSafeToWrite($configFile);
        [$keptSettings, $removedSettings] = $this->keptSettings($configFile, $config);
        $settings = $config + $keptSettings;

        try {
            if (!$this->filesystem->exists($configFile)) {
                $this->filesystem->mkdir(\dirname($configFile));
                $this->filesystem->touch($configFile);
                $this->filesystem->chmod($configFile, 0o600);
            }

            $this->filesystem->dumpFile($configFile, RoundTripYaml::dump($settings, 2, 4));
            $this->filesystem->chmod($configFile, 0o600);
        } catch (IOException $ioException) {
            throw StandaloneConfigWriteException::fromIOException($configFile, $ioException);
        }

        return $removedSettings;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array{array<array-key, mixed>, list<string>}
     */
    private function keptSettings(string $configFile, array $config): array
    {
        $existingSettings = $this->existingSettings($configFile);

        return $this->switchesProvider($config, $existingSettings)
            ? $this->providerBoundSettings->removedFrom($existingSettings)
            : [$existingSettings, []];
    }

    /**
     * @param array<string, mixed>    $config
     * @param array<array-key, mixed> $existingSettings
     */
    private function switchesProvider(array $config, array $existingSettings): bool
    {
        return \array_key_exists('provider', $config) && $config['provider'] !== ($existingSettings['provider'] ?? null);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function existingSettings(string $configFile): array
    {
        try {
            return $this->standaloneConfigFileReader->read($configFile);
        } catch (MalformedProjectConfigException) {
            return [];
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
