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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use JsonException;
use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\InstalledPackagesReaderInterface;

use function Symfony\Component\String\b;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class LockfileInstalledPackagesReader implements InstalledPackagesReaderInterface
{
    public function __construct(
        private Filesystem $filesystem,
        private LoggerInterface $logger,
    ) {}

    #[Override]
    public function read(string $projectPath): ?array
    {
        $lockfilePath = \sprintf('%s/composer.lock', b($projectPath)->trimEnd('/')->toString());
        $readablePath = $this->readablePath($lockfilePath, $projectPath);
        $lock = null === $readablePath ? null : $this->decode($readablePath, $lockfilePath);

        return null === $lock ? null : $this->packagesOf($lock);
    }

    private function readablePath(string $lockfilePath, string $projectPath): ?string
    {
        if (!$this->filesystem->exists($lockfilePath)) {
            return null;
        }

        $readablePath = LockfileSymlinkResolver::resolve($lockfilePath, $projectPath);
        if (null === $readablePath) {
            $this->logger->warning("composer.lock is a symlink that does not lead to a regular file inside the project; auditing without the project's package list", ['path' => $lockfilePath]);

            return null;
        }

        if (filesize($readablePath) > LockfileHasher::MAX_LOCKFILE_BYTES) {
            $this->logger->warning("composer.lock is too large; auditing without the project's package list", ['path' => $lockfilePath, 'limit_bytes' => LockfileHasher::MAX_LOCKFILE_BYTES]);

            return null;
        }

        return $readablePath;
    }

    /**
     * @return array<mixed>|null
     */
    private function decode(string $readablePath, string $lockfilePath): ?array
    {
        try {
            $lock = json_decode($this->filesystem->readFile($readablePath), true, flags: \JSON_THROW_ON_ERROR);
        } catch (IOException $ioException) {
            $this->logger->warning("composer.lock is unreadable; auditing without the project's package list", ['path' => $lockfilePath, 'error' => $ioException->getMessage()]);

            return null;
        } catch (JsonException $jsonException) {
            $this->logger->warning("composer.lock is not valid JSON; auditing without the project's package list", ['path' => $lockfilePath, 'error' => $jsonException->getMessage()]);

            return null;
        }

        return \is_array($lock) ? $lock : null;
    }

    /**
     * @param array<mixed> $lock
     *
     * @return array<string, string>|null
     */
    private function packagesOf(array $lock): ?array
    {
        $packageLists = array_filter([$lock['packages'] ?? null, $lock['packages-dev'] ?? null], \is_array(...));
        if ([] === $packageLists) {
            return null;
        }

        $packages = [];
        foreach ($packageLists as $packageList) {
            foreach ($packageList as $package) {
                $packages = [...$packages, ...$this->nameAndVersionOf($package)];
            }
        }

        return $packages;
    }

    /**
     * @return array<string, string>
     */
    private function nameAndVersionOf(mixed $package): array
    {
        if (!\is_array($package) || !\is_string($package['name'] ?? null) || !\is_string($package['version'] ?? null)) {
            return [];
        }

        return [$package['name'] => $package['version']];
    }
}
