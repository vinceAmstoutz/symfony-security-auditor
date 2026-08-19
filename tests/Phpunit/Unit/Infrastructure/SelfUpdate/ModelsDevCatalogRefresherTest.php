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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ModelsDevCatalogRefresher;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PricingCatalogRefreshOutcome;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ReleaseClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate\Fixture\RemovalFailingFilesystem;

final class ModelsDevCatalogRefresherTest extends TestCase
{
    private const string VALID_CATALOG = '{"anthropic":{"models":{"claude-opus-5":{"cost":{"input":5,"output":25}}}}}';

    private string $cacheDir;

    #[Override]
    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir().'/ssa-catalog-refresh-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->cacheDir);
    }

    public function test_it_downloads_the_catalog_to_the_cache_directory(): void
    {
        $releaseClient = $this->releaseClientWriting(self::VALID_CATALOG);

        $pricingCatalogRefreshOutcome = (new ModelsDevCatalogRefresher($releaseClient, $this->cacheDir, self::createStub(LoggerInterface::class)))->refresh();

        self::assertSame(PricingCatalogRefreshOutcome::Refreshed, $pricingCatalogRefreshOutcome);
        self::assertFileExists($this->cacheDir.'/models-dev.json');
        self::assertStringEqualsFile($this->cacheDir.'/models-dev.json', self::VALID_CATALOG);
    }

    public function test_it_downloads_from_the_symfony_models_dev_raw_catalog_url(): void
    {
        $releaseClient = self::createMock(ReleaseClientInterface::class);
        $releaseClient->expects(self::once())
            ->method('download')
            ->with(
                'https://raw.githubusercontent.com/symfony/models-dev/main/models-dev.json',
                self::callback(fn (string $destination): bool => str_starts_with($destination, $this->cacheDir.'/') && $destination !== $this->cacheDir.'/models-dev.json'),
            )
            ->willReturnCallback(static function (string $url, string $destination): void {
                (new Filesystem())->dumpFile($destination, self::VALID_CATALOG);
            });

        (new ModelsDevCatalogRefresher($releaseClient, $this->cacheDir, self::createStub(LoggerInterface::class)))->refresh();

        self::assertFileExists($this->cacheDir.'/models-dev.json');
    }

    public function test_it_never_overwrites_an_existing_catalog_with_an_invalid_download(): void
    {
        (new Filesystem())->dumpFile($this->cacheDir.'/models-dev.json', '{"anthropic":{}}');

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Could not refresh the bundled pricing catalog',
            self::callback(static fn (array $context): bool => \array_key_exists('exception', $context)),
        );

        $pricingCatalogRefreshOutcome = (new ModelsDevCatalogRefresher($this->releaseClientWriting('this is not json'), $this->cacheDir, $logger))->refresh();

        self::assertSame(PricingCatalogRefreshOutcome::Failed, $pricingCatalogRefreshOutcome);
        self::assertStringEqualsFile($this->cacheDir.'/models-dev.json', '{"anthropic":{}}');
        self::assertSame(['models-dev.json'], $this->filesInCacheDir());
    }

    public function test_it_never_installs_a_json_document_that_carries_no_model_pricing(): void
    {
        (new Filesystem())->dumpFile($this->cacheDir.'/models-dev.json', self::VALID_CATALOG);

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Could not refresh the bundled pricing catalog',
            self::callback(static fn (array $context): bool => \is_string($context['exception'] ?? null) && str_contains($context['exception'], 'carries no model pricing')),
        );

        $pricingCatalogRefreshOutcome = (new ModelsDevCatalogRefresher($this->releaseClientWriting('{"message":"Not Found"}'), $this->cacheDir, $logger))->refresh();

        self::assertSame(PricingCatalogRefreshOutcome::Failed, $pricingCatalogRefreshOutcome);
        self::assertStringEqualsFile($this->cacheDir.'/models-dev.json', self::VALID_CATALOG);
    }

    public function test_it_never_installs_a_provider_entry_without_a_models_map(): void
    {
        $logger = self::createStub(LoggerInterface::class);

        $pricingCatalogRefreshOutcome = (new ModelsDevCatalogRefresher($this->releaseClientWriting('{"anthropic":{"api":"https://api.anthropic.com"}}'), $this->cacheDir, $logger))->refresh();

        self::assertSame(PricingCatalogRefreshOutcome::Failed, $pricingCatalogRefreshOutcome);
        self::assertFileDoesNotExist($this->cacheDir.'/models-dev.json');
    }

    public function test_it_never_installs_a_provider_entry_whose_models_carry_no_cost(): void
    {
        $logger = self::createStub(LoggerInterface::class);

        $pricingCatalogRefreshOutcome = (new ModelsDevCatalogRefresher($this->releaseClientWriting('{"anthropic":{"models":{"claude-opus-5":{}}}}'), $this->cacheDir, $logger))->refresh();

        self::assertSame(PricingCatalogRefreshOutcome::Failed, $pricingCatalogRefreshOutcome);
        self::assertFileDoesNotExist($this->cacheDir.'/models-dev.json');
    }

    public function test_it_never_installs_a_download_that_decodes_to_a_non_array_value(): void
    {
        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Could not refresh the bundled pricing catalog',
            self::callback(static fn (array $context): bool => \array_key_exists('exception', $context)),
        );

        (new ModelsDevCatalogRefresher($this->releaseClientWriting('"just a string"'), $this->cacheDir, $logger))->refresh();

        self::assertFileDoesNotExist($this->cacheDir.'/models-dev.json');
    }

    public function test_it_logs_and_does_not_throw_when_the_downloaded_file_disappears_before_validation(): void
    {
        $releaseClient = self::createStub(ReleaseClientInterface::class);
        $releaseClient->method('download')->willReturnCallback(
            static function (string $url, string $destination): void {
                (new Filesystem())->dumpFile($destination, '{}');
                unlink($destination);
            },
        );

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Could not refresh the bundled pricing catalog',
            self::callback(static fn (array $context): bool => \is_string($context['exception'] ?? null) && str_contains($context['exception'], 'Could not read the downloaded catalog')),
        );

        (new ModelsDevCatalogRefresher($releaseClient, $this->cacheDir, $logger))->refresh();

        self::assertFileDoesNotExist($this->cacheDir.'/models-dev.json');
    }

    public function test_it_logs_and_does_not_throw_when_removing_an_invalid_download_fails(): void
    {
        $releaseClient = $this->releaseClientWriting('this is not json');

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::exactly(2))->method('warning')->with(
            self::logicalOr('Could not refresh the bundled pricing catalog', 'Could not remove the leftover pricing catalog download'),
            self::callback(static fn (array $context): bool => \array_key_exists('exception', $context)),
        );

        (new ModelsDevCatalogRefresher($releaseClient, $this->cacheDir, $logger, new RemovalFailingFilesystem()))->refresh();
    }

    public function test_it_replaces_an_existing_catalog_with_a_valid_download(): void
    {
        (new Filesystem())->dumpFile($this->cacheDir.'/models-dev.json', '{"stale":{}}');

        (new ModelsDevCatalogRefresher($this->releaseClientWriting(self::VALID_CATALOG), $this->cacheDir, self::createStub(LoggerInterface::class)))->refresh();

        self::assertStringEqualsFile($this->cacheDir.'/models-dev.json', self::VALID_CATALOG);
    }

    public function test_it_logs_and_does_not_throw_when_installing_the_download_fails(): void
    {
        (new Filesystem())->mkdir($this->cacheDir.'/models-dev.json');

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Could not refresh the bundled pricing catalog',
            self::callback(static fn (array $context): bool => \array_key_exists('exception', $context)),
        );

        (new ModelsDevCatalogRefresher($this->releaseClientWriting(self::VALID_CATALOG), $this->cacheDir, $logger))->refresh();

        self::assertDirectoryExists($this->cacheDir.'/models-dev.json');
        self::assertSame(['models-dev.json'], $this->filesInCacheDir());
    }

    public function test_it_creates_the_cache_directory_when_missing(): void
    {
        self::assertDirectoryDoesNotExist($this->cacheDir);

        (new ModelsDevCatalogRefresher($this->releaseClientWriting(self::VALID_CATALOG), $this->cacheDir, self::createStub(LoggerInterface::class)))->refresh();

        self::assertDirectoryExists($this->cacheDir);
    }

    public function test_it_logs_and_does_not_throw_when_the_download_fails(): void
    {
        $releaseClient = self::createStub(ReleaseClientInterface::class);
        $releaseClient->method('download')->willThrowException(SelfUpdateFailedException::forFailedDownload('https://raw.githubusercontent.com/symfony/models-dev/main/models-dev.json'));

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Could not refresh the bundled pricing catalog',
            self::callback(static fn (array $context): bool => \array_key_exists('exception', $context)),
        );

        (new ModelsDevCatalogRefresher($releaseClient, $this->cacheDir, $logger))->refresh();

        self::assertFileDoesNotExist($this->cacheDir.'/models-dev.json');
        self::assertSame([], $this->filesInCacheDir());
    }

    public function test_it_logs_and_does_not_throw_when_the_cache_directory_cannot_be_created(): void
    {
        (new Filesystem())->dumpFile($this->cacheDir, 'a file, not a directory, already occupies this path');

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Could not refresh the bundled pricing catalog',
            self::callback(static fn (array $context): bool => \array_key_exists('exception', $context)),
        );

        (new ModelsDevCatalogRefresher($this->releaseClientWriting(self::VALID_CATALOG), $this->cacheDir, $logger))->refresh();
    }

    private function releaseClientWriting(string $payload): ReleaseClientInterface
    {
        $releaseClient = self::createStub(ReleaseClientInterface::class);
        $releaseClient->method('download')->willReturnCallback(
            static function (string $url, string $destination) use ($payload): void {
                (new Filesystem())->dumpFile($destination, $payload);
            },
        );

        return $releaseClient;
    }

    /**
     * @return list<string>
     */
    private function filesInCacheDir(): array
    {
        $entries = scandir($this->cacheDir);
        self::assertNotFalse($entries);

        return array_values(array_diff($entries, ['.', '..']));
    }
}
