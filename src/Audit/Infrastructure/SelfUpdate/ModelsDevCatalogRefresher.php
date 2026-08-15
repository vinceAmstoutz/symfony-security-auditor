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

use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOExceptionInterface;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;

/**
 * Downloads the latest `symfony/models-dev` catalog snapshot to a writable
 * override location — `ModelsDevPricingProvider` checks it before falling
 * back to the catalog frozen into the binary at build time. The only route a
 * standalone install otherwise has to a fresher catalog is a whole new
 * tagged release.
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
    public function refresh(): void
    {
        $destination = \sprintf('%s/%s', $this->cacheDir, self::CATALOG_FILENAME);

        try {
            $this->filesystem->mkdir($this->cacheDir);
            $this->releaseClient->download(self::CATALOG_URL, $destination);
        } catch (SelfUpdateFailedException|IOExceptionInterface $exception) {
            $this->logger->warning('Could not refresh the bundled pricing catalog', [
                'exception' => $exception->getMessage(),
            ]);
        }
    }
}
