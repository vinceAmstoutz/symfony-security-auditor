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
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOExceptionInterface;
use Symfony\Component\Filesystem\Filesystem;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;

/**
 * Downloads the latest `symfony/models-dev` catalog snapshot to a writable
 * override location — `ModelsDevPricingProvider` checks it before falling
 * back to the catalog frozen into the binary at build time. The only route a
 * standalone install otherwise has to a fresher catalog is a whole new
 * tagged release.
 *
 * The download lands in a temp file first and is only moved into place once
 * it has been confirmed to decode as JSON *and* to carry at least one
 * priced model, so neither a truncated transfer nor an unrelated document
 * served in its place can overwrite a working catalog. The URL tracks
 * upstream `main` on purpose — a pinned ref would freeze the catalog at the
 * same staleness a new tagged release already fixes.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ModelsDevCatalogRefresher implements PricingCatalogRefresherInterface
{
    private const string CATALOG_URL = 'https://raw.githubusercontent.com/symfony/models-dev/main/models-dev.json';

    public const string CATALOG_FILENAME = 'models-dev.json';

    public function __construct(
        private ReleaseClientInterface $releaseClient,
        private string $cacheDir,
        private LoggerInterface $logger,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    #[Override]
    public function refresh(): PricingCatalogRefreshOutcome
    {
        try {
            $this->filesystem->mkdir($this->cacheDir);
            $downloadPath = $this->filesystem->tempnam($this->cacheDir, \sprintf('.%s.', self::CATALOG_FILENAME), '.download');
        } catch (IOExceptionInterface $ioException) {
            return $this->failed($ioException);
        }

        try {
            $this->releaseClient->download(self::CATALOG_URL, $downloadPath);
            $this->assertValidCatalog($downloadPath);
            $this->filesystem->rename($downloadPath, \sprintf('%s/%s', $this->cacheDir, self::CATALOG_FILENAME), true);
        } catch (SelfUpdateFailedException|IOExceptionInterface $exception) {
            $this->removeLeftoverDownload($downloadPath);

            return $this->failed($exception);
        }

        return PricingCatalogRefreshOutcome::Refreshed;
    }

    private function failed(Throwable $throwable): PricingCatalogRefreshOutcome
    {
        $this->logger->warning('Could not refresh the bundled pricing catalog', [
            'exception' => $throwable->getMessage(),
        ]);

        return PricingCatalogRefreshOutcome::Failed;
    }

    private function removeLeftoverDownload(string $downloadPath): void
    {
        try {
            $this->filesystem->remove($downloadPath);
        } catch (IOExceptionInterface $ioException) {
            $this->logger->warning('Could not remove the leftover pricing catalog download', [
                'exception' => $ioException->getMessage(),
            ]);
        }
    }

    /**
     * @throws SelfUpdateFailedException
     */
    private function assertValidCatalog(string $downloadPath): void
    {
        $contents = is_file($downloadPath) ? file_get_contents($downloadPath) : false;
        if (false === $contents) {
            throw SelfUpdateFailedException::forUnreadableCatalogDownload($downloadPath);
        }

        try {
            $decoded = json_decode($contents, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw SelfUpdateFailedException::forInvalidCatalogDownload(self::CATALOG_URL);
        }

        if (!\is_array($decoded)) {
            throw SelfUpdateFailedException::forInvalidCatalogDownload(self::CATALOG_URL);
        }

        if (!$this->containsAnyModelPrice($decoded)) {
            throw SelfUpdateFailedException::forUnrecognizedCatalogDownload(self::CATALOG_URL);
        }
    }

    /**
     * @param array<array-key, mixed> $catalog
     */
    private function containsAnyModelPrice(array $catalog): bool
    {
        foreach ($catalog as $provider) {
            if (\is_array($provider) && $this->hasPricedModel($provider)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<array-key, mixed> $provider
     */
    private function hasPricedModel(array $provider): bool
    {
        $models = $provider['models'] ?? null;
        if (!\is_array($models)) {
            return false;
        }

        foreach ($models as $model) {
            if (\is_array($model) && \is_array($model['cost'] ?? null)) {
                return true;
            }
        }

        return false;
    }
}
