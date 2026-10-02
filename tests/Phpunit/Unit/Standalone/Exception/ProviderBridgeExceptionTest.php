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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Standalone\Exception;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\ProviderBridgeException;

final class ProviderBridgeExceptionTest extends TestCase
{
    public function test_a_missing_bridge_is_answered_with_the_init_command_instead_of_composer_require(): void
    {
        $runtimeException = new RuntimeException('Anthropic platform configuration requires "symfony/ai-anthropic-platform" package. Try running "composer require symfony/ai-anthropic-platform".');

        $providerBridgeException = ProviderBridgeException::forBundleFailure($runtimeException);

        self::assertInstanceOf(ProviderBridgeException::class, $providerBridgeException);
        self::assertSame(
            'The "anthropic" provider bridge (symfony/ai-anthropic-platform) is not installed under the standalone data directory. Run "symfony-security-auditor init --provider=anthropic" to download it; a "composer require" in the audited project does not help, the binary never loads that project\'s vendor directory.',
            $providerBridgeException->getMessage(),
        );
        self::assertNull($providerBridgeException->getPrevious(), 'the console renders every previous exception, which would print the "composer require" advice this one replaces');
    }

    public function test_the_advice_names_the_platform_behind_a_hyphenated_package(): void
    {
        $runtimeException = new RuntimeException('OpenAI platform configuration requires "symfony/ai-open-ai-platform" package. Try running "composer require symfony/ai-open-ai-platform".');

        $providerBridgeException = ProviderBridgeException::forBundleFailure($runtimeException);

        self::assertInstanceOf(ProviderBridgeException::class, $providerBridgeException);
        self::assertStringContainsString('The "openai" provider bridge (symfony/ai-open-ai-platform)', $providerBridgeException->getMessage());
        self::assertStringContainsString('init --provider=openai"', $providerBridgeException->getMessage());
    }

    public function test_the_advice_asks_for_an_instance_on_an_instance_keyed_platform(): void
    {
        $runtimeException = new RuntimeException('Generic platform configuration requires "symfony/ai-generic-platform" package. Try running "composer require symfony/ai-generic-platform".');

        $providerBridgeException = ProviderBridgeException::forBundleFailure($runtimeException);

        self::assertInstanceOf(ProviderBridgeException::class, $providerBridgeException);
        self::assertStringContainsString('init --provider=generic.<instance>"', $providerBridgeException->getMessage());
    }

    public function test_a_platform_wrapping_others_is_answered_with_why_the_binary_cannot_run_it(): void
    {
        $runtimeException = new RuntimeException('Failover platform configuration requires "symfony/ai-failover-platform" package. Try running "composer require symfony/ai-failover-platform".');

        $providerBridgeException = ProviderBridgeException::forBundleFailure($runtimeException);

        self::assertInstanceOf(ProviderBridgeException::class, $providerBridgeException);
        self::assertSame(
            'The "failover" platform wraps other platforms through a rate limiter service that only a Symfony application defines, so the standalone binary cannot run it. Configure the platform it wraps directly, or run the audit through the Symfony bundle.',
            $providerBridgeException->getMessage(),
        );
        self::assertNull($providerBridgeException->getPrevious(), 'the console renders every previous exception, which would print the "composer require" advice this one replaces');
    }

    public function test_any_other_bundle_failure_is_not_a_bridge_problem(): void
    {
        self::assertNull(ProviderBridgeException::forBundleFailure(new RuntimeException('Agent configuration requires "symfony/ai-agent" package. Try running "composer require symfony/ai-agent".')));
    }
}
