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

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Platform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\OllamaPlatformProviderFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\PlatformConnection;

final class OllamaPlatformProviderFactoryTest extends TestCase
{
    public function test_it_reports_the_ollama_provider_name(): void
    {
        self::assertSame('ollama', (new OllamaPlatformProviderFactory())->provider());
    }

    public function test_it_builds_a_local_platform_without_an_api_key(): void
    {
        $platform = (new OllamaPlatformProviderFactory())->create(
            new PlatformConnection('ollama', endpoint: 'http://localhost:11434'),
        );

        self::assertInstanceOf(Platform::class, $platform);
    }
}
