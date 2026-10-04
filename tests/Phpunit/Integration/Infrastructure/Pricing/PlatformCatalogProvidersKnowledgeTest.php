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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\Pricing;

use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PlatformCatalogProviders;

/**
 * `PlatformCatalogProviders` pairs a `symfony/ai-bundle` platform name with a
 * `symfony/models-dev` provider key, two vocabularies that each upstream may
 * rename on its own. Reading both back keeps a renamed key from silently
 * sending every model on that platform to the catalog-wide fallback.
 */
final class PlatformCatalogProvidersKnowledgeTest extends TestCase
{
    private const string PLATFORM_CONFIG_DIRECTORY = __DIR__.'/../../../../../vendor/symfony/ai-bundle/config/platform';

    /** @var array<array-key, mixed>|null */
    private static ?array $installedCatalog = null;

    #[DataProvider('mappedPlatformCases')]
    public function test_the_platform_is_one_symfony_ai_bundle_declares(string $platform, string $catalogProvider): void
    {
        self::assertFileExists(
            \sprintf('%s/%s.php', self::PLATFORM_CONFIG_DIRECTORY, $platform),
            \sprintf('Pricing reads "%s" for a platform named "%s", which symfony/ai-bundle no longer declares.', $catalogProvider, $platform),
        );
    }

    /**
     * @throws JsonException
     */
    #[DataProvider('mappedPlatformCases')]
    public function test_the_listing_the_platform_is_priced_from_is_in_the_installed_catalog(string $platform, string $catalogProvider): void
    {
        self::assertArrayHasKey($catalogProvider, $this->installedCatalog(), \sprintf('"%s" is priced from a catalog provider the installed symfony/models-dev no longer lists.', $platform));
    }

    /** @return iterable<string, array{string, string}> */
    public static function mappedPlatformCases(): iterable
    {
        foreach (PlatformCatalogProviders::PROVIDERS as $platform => $catalogProvider) {
            yield $platform => [$platform, $catalogProvider];
        }
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws JsonException
     */
    private function installedCatalog(): array
    {
        return self::$installedCatalog ??= $this->decodedInstalledCatalog();
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws JsonException
     */
    private function decodedInstalledCatalog(): array
    {
        $catalogPath = (new ModelsDevPricingProvider(new NullLogger()))->packagedCatalogPath();
        self::assertNotNull($catalogPath);

        $contents = file_get_contents($catalogPath);
        self::assertIsString($contents);

        $catalog = json_decode($contents, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($catalog);

        return $catalog;
    }
}
