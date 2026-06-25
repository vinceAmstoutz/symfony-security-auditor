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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Platform;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Platform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\AnthropicPlatformProviderFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\Exception\MissingPlatformApiKeyException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\OpenAiPlatformProviderFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\PlatformConnection;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\PlatformProviderFactoryInterface;

final class ApiKeyPlatformProviderFactoryTest extends TestCase
{
    #[DataProvider('apiKeyProviderFactories')]
    public function test_it_reports_its_provider_name(PlatformProviderFactoryInterface $platformProviderFactory, string $expectedProvider): void
    {
        self::assertSame($expectedProvider, $platformProviderFactory->provider());
    }

    #[DataProvider('apiKeyProviderFactories')]
    public function test_it_builds_a_platform_from_an_api_key(PlatformProviderFactoryInterface $platformProviderFactory, string $provider): void
    {
        $platform = $platformProviderFactory->create(new PlatformConnection($provider, 'sk-test-key'));

        self::assertInstanceOf(Platform::class, $platform);
    }

    #[DataProvider('apiKeyProviderFactories')]
    public function test_it_rejects_a_missing_api_key(PlatformProviderFactoryInterface $platformProviderFactory, string $provider): void
    {
        $this->expectException(MissingPlatformApiKeyException::class);

        $platformProviderFactory->create(new PlatformConnection($provider));
    }

    /**
     * @return iterable<string, array{PlatformProviderFactoryInterface, string}>
     */
    public static function apiKeyProviderFactories(): iterable
    {
        yield 'anthropic' => [new AnthropicPlatformProviderFactory(), 'anthropic'];
        yield 'openai' => [new OpenAiPlatformProviderFactory(), 'openai'];
    }
}
