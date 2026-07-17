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

use JsonException;
use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SelfUpdater implements SelfUpdaterInterface
{
    private const string LATEST_RELEASE_API_URL = 'https://api.github.com/repos/vinceAmstoutz/symfony-security-auditor/releases/latest';

    public function __construct(
        private ReleaseClientInterface $releaseClient,
        private GitHubBinaryAssetResolver $gitHubBinaryAssetResolver,
        private RunningBinaryLocatorInterface $runningBinaryLocator,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    #[Override]
    public function run(string $currentVersion, bool $checkOnly): SelfUpdateResult
    {
        $latestVersion = $this->latestVersion();

        if (!version_compare($latestVersion, $currentVersion, '>')) {
            return new SelfUpdateResult(SelfUpdateStatus::AlreadyUpToDate, $currentVersion, $latestVersion);
        }

        if ($checkOnly) {
            return new SelfUpdateResult(SelfUpdateStatus::UpdateAvailable, $currentVersion, $latestVersion);
        }

        $this->replaceBinary($this->gitHubBinaryAssetResolver->resolve($latestVersion));

        return new SelfUpdateResult(SelfUpdateStatus::Updated, $currentVersion, $latestVersion);
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function latestVersion(): string
    {
        $payload = $this->releaseClient->get(self::LATEST_RELEASE_API_URL);

        try {
            $decoded = json_decode($payload, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw SelfUpdateFailedException::forUnresolvableLatestVersion(self::LATEST_RELEASE_API_URL, $jsonException);
        }

        if (!\is_array($decoded) || !\array_key_exists('tag_name', $decoded) || !\is_string($decoded['tag_name']) || '' === $decoded['tag_name']) {
            throw SelfUpdateFailedException::forUnresolvableLatestVersion(self::LATEST_RELEASE_API_URL);
        }

        return $decoded['tag_name'];
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function replaceBinary(GitHubBinaryAsset $gitHubBinaryAsset): void
    {
        $binaryPath = $this->runningBinaryLocator->path();
        if (!is_writable($binaryPath)) {
            throw SelfUpdateFailedException::forUnwritableBinary($binaryPath);
        }

        $downloadPath = $this->filesystem->tempnam(\dirname($binaryPath), \sprintf('.%s.', $gitHubBinaryAsset->name), '.download');

        try {
            $this->releaseClient->download($gitHubBinaryAsset->downloadUrl, $downloadPath);
            $this->assertChecksumMatches($gitHubBinaryAsset, $downloadPath);
            $this->install($downloadPath, $binaryPath);
        } catch (SelfUpdateFailedException $selfUpdateFailedException) {
            $this->filesystem->remove($downloadPath);

            throw $selfUpdateFailedException;
        }
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function assertChecksumMatches(GitHubBinaryAsset $gitHubBinaryAsset, string $downloadPath): void
    {
        $actual = hash_file('sha256', $downloadPath);
        \assert(false !== $actual);

        if (!hash_equals($this->expectedChecksum($gitHubBinaryAsset), $actual)) {
            throw SelfUpdateFailedException::forChecksumMismatch($gitHubBinaryAsset->name);
        }
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function expectedChecksum(GitHubBinaryAsset $gitHubBinaryAsset): string
    {
        return explode(' ', trim($this->releaseClient->get($gitHubBinaryAsset->checksumUrl)))[0];
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function install(string $downloadPath, string $binaryPath): void
    {
        try {
            $this->filesystem->chmod($downloadPath, 0o755);
            $this->filesystem->rename($downloadPath, $binaryPath, true);
        } catch (IOException $ioException) {
            throw SelfUpdateFailedException::forFailedReplacement($binaryPath, $ioException);
        }
    }
}
