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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PricingPlatformPass;

final class PricingPlatformPassTest extends TestCase
{
    #[DataProvider('aliasedPlatformCases')]
    public function test_it_publishes_the_platform_the_platform_interface_is_aliased_to(string $platformServiceId, string $expectedPlatform): void
    {
        $containerBuilder = new ContainerBuilder();
        $containerBuilder->setAlias(PlatformInterface::class, $platformServiceId);

        (new PricingPlatformPass())->process($containerBuilder);

        self::assertSame($expectedPlatform, $containerBuilder->getParameter(PricingPlatformPass::PARAMETER));
    }

    /** @return iterable<string, array{string, string}> */
    public static function aliasedPlatformCases(): iterable
    {
        yield 'a single-connection platform' => ['ai.platform.together', 'together'];
        yield 'an instance of an instance-keyed platform' => ['ai.platform.generic.my_gateway', 'generic'];
    }

    public function test_it_publishes_no_platform_when_the_alias_targets_a_service_of_the_application(): void
    {
        $containerBuilder = new ContainerBuilder();
        $containerBuilder->setAlias(PlatformInterface::class, 'app.platform');

        (new PricingPlatformPass())->process($containerBuilder);

        self::assertNull($containerBuilder->getParameter(PricingPlatformPass::PARAMETER));
    }

    public function test_it_publishes_no_platform_when_the_platform_interface_is_not_an_alias(): void
    {
        $containerBuilder = new ContainerBuilder();
        $containerBuilder->register(PlatformInterface::class);

        (new PricingPlatformPass())->process($containerBuilder);

        self::assertTrue($containerBuilder->hasParameter(PricingPlatformPass::PARAMETER));
        self::assertNull($containerBuilder->getParameter(PricingPlatformPass::PARAMETER));
    }
}
