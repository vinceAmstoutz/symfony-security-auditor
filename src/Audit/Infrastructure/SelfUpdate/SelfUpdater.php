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

use Closure;
use JsonException;
use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;

use function Symfony\Component\String\u;

/**
 * Compares and reports a release tag without its leading `v` but builds asset
 * URLs from the tag as published, refusing a tag outside `ReleaseTag`'s
 * grammar. On the snapshot channel or from a snapshot binary, installs the
 * latest version whenever it differs from the running one.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SelfUpdater implements SelfUpdaterInterface
{
    private const string LATEST_RELEASE_API_URL = 'https://api.github.com/repos/vinceAmstoutz/symfony-security-auditor/releases/latest';

    private const string SNAPSHOT_TAG = 'snapshot';

    private const string SNAPSHOT_RELEASE_API_URL = 'https://api.github.com/repos/vinceAmstoutz/symfony-security-auditor/releases/tags/snapshot';

    public function __construct(
        private ReleaseClientInterface $releaseClient,
        private GitHubBinaryAssetResolver $gitHubBinaryAssetResolver,
        private RunningBinaryLocatorInterface $runningBinaryLocator,
        private BinarySwapSchedulerInterface $binarySwapScheduler,
        private Filesystem $filesystem = new Filesystem(),
        private PricingCatalogRefresherInterface $pricingCatalogRefresher = new NullPricingCatalogRefresher(),
    ) {}

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    #[Override]
    public function run(string $currentVersion, bool $checkOnly, ReleaseChannel $releaseChannel = ReleaseChannel::Stable, ?Closure $onDownloadProgress = null): SelfUpdateResult
    {
        $this->gitHubBinaryAssetResolver->assertSupportedPlatform();

        [$latestTag, $latestVersion] = match ($releaseChannel) {
            ReleaseChannel::Stable => $this->latestRelease(),
            ReleaseChannel::Snapshot => [self::SNAPSHOT_TAG, $this->snapshotVersion()],
        };

        if (!$this->replacesRunningVersion($releaseChannel, $latestVersion, $currentVersion)) {
            return new SelfUpdateResult(
                SelfUpdateStatus::AlreadyUpToDate,
                $currentVersion,
                $latestVersion,
                $this->refreshUnlessProbing($checkOnly),
            );
        }

        if ($checkOnly) {
            return new SelfUpdateResult(SelfUpdateStatus::UpdateAvailable, $currentVersion, $latestVersion);
        }

        $this->replaceBinary($this->gitHubBinaryAssetResolver->resolve($latestTag), $onDownloadProgress);

        return new SelfUpdateResult(
            SelfUpdateStatus::Updated,
            $currentVersion,
            $latestVersion,
            $this->pricingCatalogRefresher->refresh(),
        );
    }

    private function refreshUnlessProbing(bool $checkOnly): PricingCatalogRefreshOutcome
    {
        return $checkOnly ? PricingCatalogRefreshOutcome::Skipped : $this->pricingCatalogRefresher->refresh();
    }

    private function replacesRunningVersion(ReleaseChannel $releaseChannel, string $latestVersion, string $currentVersion): bool
    {
        if (ReleaseChannel::Snapshot === $releaseChannel || SnapshotVersion::isValid($currentVersion)) {
            return $latestVersion !== $currentVersion;
        }

        return version_compare($latestVersion, $currentVersion, '>');
    }

    /**
     * @return array{string, string} the release tag, then the version it carries
     *
     * @throws SelfUpdateFailedException
     */
    private function latestRelease(): array
    {
        $latestTag = $this->releaseField(self::LATEST_RELEASE_API_URL, 'tag_name');
        if (!ReleaseTag::isValid($latestTag)) {
            throw SelfUpdateFailedException::forUnresolvableLatestVersion(self::LATEST_RELEASE_API_URL);
        }

        return [$latestTag, u($latestTag)->trimPrefix(['v', 'V'])->toString()];
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function snapshotVersion(): string
    {
        $snapshotVersion = $this->releaseField(self::SNAPSHOT_RELEASE_API_URL, 'name');
        if (!SnapshotVersion::isValid($snapshotVersion)) {
            throw SelfUpdateFailedException::forUnresolvableLatestVersion(self::SNAPSHOT_RELEASE_API_URL);
        }

        return $snapshotVersion;
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function releaseField(string $url, string $field): string
    {
        $payload = $this->releaseClient->get($url);

        try {
            $decoded = json_decode($payload, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw SelfUpdateFailedException::forUnresolvableLatestVersion($url, $jsonException);
        }

        if (!\is_array($decoded) || !\array_key_exists($field, $decoded) || !\is_string($decoded[$field])) {
            throw SelfUpdateFailedException::forUnresolvableLatestVersion($url);
        }

        return $decoded[$field];
    }

    /**
     * @param (Closure(int): void)|null $onDownloadProgress
     *
     * @throws SelfUpdateFailedException
     */
    private function replaceBinary(GitHubBinaryAsset $gitHubBinaryAsset, ?Closure $onDownloadProgress): void
    {
        $binaryPath = $this->runningBinaryLocator->path();
        $downloadPath = $this->stageDownloadNextTo($binaryPath, $gitHubBinaryAsset);

        try {
            $this->releaseClient->download($gitHubBinaryAsset->downloadUrl, $downloadPath, $onDownloadProgress);
            $this->assertChecksumMatches($gitHubBinaryAsset, $downloadPath);
            $this->scheduleInstall($downloadPath, $binaryPath);
        } catch (Throwable $throwable) {
            $this->discardDownload($downloadPath);

            throw $throwable;
        }
    }

    /**
     * Fails before any download when the binary's directory is not writable:
     * the binary is replaced by a rename in it.
     *
     * @throws SelfUpdateFailedException
     */
    private function stageDownloadNextTo(string $binaryPath, GitHubBinaryAsset $gitHubBinaryAsset): string
    {
        $directory = \dirname($binaryPath);

        try {
            return $this->filesystem->tempnam($directory, \sprintf('.%s.', $gitHubBinaryAsset->name), '.download');
        } catch (IOException $ioException) {
            throw SelfUpdateFailedException::forUnwritableBinaryDirectory($directory, $ioException);
        }
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function assertChecksumMatches(GitHubBinaryAsset $gitHubBinaryAsset, string $downloadPath): void
    {
        $actual = is_readable($downloadPath) ? hash_file('sha256', $downloadPath) : false;
        if (false === $actual) {
            throw SelfUpdateFailedException::forUnreadableDownload($downloadPath);
        }

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
    private function scheduleInstall(string $downloadPath, string $binaryPath): void
    {
        try {
            $this->filesystem->chmod($downloadPath, 0o755);
        } catch (IOException $ioException) {
            throw SelfUpdateFailedException::forFailedReplacement($binaryPath, $ioException);
        }

        $this->binarySwapScheduler->schedule(function () use ($downloadPath, $binaryPath): void {
            $this->commitInstall($downloadPath, $binaryPath);
        });
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function commitInstall(string $downloadPath, string $binaryPath): void
    {
        try {
            $this->filesystem->rename($downloadPath, $binaryPath, true);
        } catch (IOException $ioException) {
            $removalFailure = $this->discardDownload($downloadPath);

            throw $removalFailure instanceof IOException ? SelfUpdateFailedException::forFailedReplacementLeavingDownload($binaryPath, $downloadPath, $ioException, $removalFailure) : SelfUpdateFailedException::forFailedReplacement($binaryPath, $ioException);
        }
    }

    private function discardDownload(string $downloadPath): ?IOException
    {
        try {
            $this->filesystem->remove($downloadPath);
        } catch (IOException $ioException) {
            return $ioException;
        }

        return null;
    }
}
