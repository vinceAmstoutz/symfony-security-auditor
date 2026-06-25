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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Platform;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\Exception\UnsupportedPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\PlatformConnection;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\StandalonePlatformFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Platform\Fixture\FakePlatformProviderFactory;

final class StandalonePlatformFactoryTest extends TestCase
{
    public function test_it_builds_the_platform_via_the_provider_factory_matching_the_connection(): void
    {
        $anthropicPlatform = self::createStub(PlatformInterface::class);
        $openAiPlatform = self::createStub(PlatformInterface::class);

        $standalonePlatformFactory = new StandalonePlatformFactory([
            new FakePlatformProviderFactory('anthropic', $anthropicPlatform),
            new FakePlatformProviderFactory('openai', $openAiPlatform),
        ]);

        self::assertSame($openAiPlatform, $standalonePlatformFactory->create(new PlatformConnection('openai', 'sk-test')));
    }

    public function test_it_rejects_a_provider_no_registered_factory_supports(): void
    {
        $standalonePlatformFactory = new StandalonePlatformFactory([
            new FakePlatformProviderFactory('anthropic', self::createStub(PlatformInterface::class)),
        ]);

        $this->expectException(UnsupportedPlatformProviderException::class);
        $this->expectExceptionMessage('Unsupported LLM provider "mistral". Supported providers: anthropic.');

        $standalonePlatformFactory->create(new PlatformConnection('mistral', 'sk-test'));
    }
}
