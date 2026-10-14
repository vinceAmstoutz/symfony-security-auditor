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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\UnselectedPlatformsPass;

final class UnselectedPlatformsPassTest extends TestCase
{
    /**
     * @param list<string> $platformServiceIds
     */
    #[DataProvider('unselectedPlatformsCases')]
    public function test_it_publishes_the_platforms_configured_when_none_is_selected(array $platformServiceIds): void
    {
        $containerBuilder = $this->containerWithPlatforms($platformServiceIds);

        (new UnselectedPlatformsPass(PlatformInterface::class))->process($containerBuilder);

        self::assertSame($platformServiceIds, $containerBuilder->getParameter(UnselectedPlatformsPass::PARAMETER));
    }

    /** @return iterable<string, array{list<string>}> */
    public static function unselectedPlatformsCases(): iterable
    {
        yield 'two platforms' => [['ai.platform.anthropic', 'ai.platform.openai']];
        yield 'three platforms' => [['ai.platform.anthropic', 'ai.platform.generic.gateway', 'ai.platform.openai']];
    }

    /**
     * @param list<string> $platformServiceIds
     */
    #[DataProvider('selectedOrSinglePlatformCases')]
    public function test_it_publishes_no_platform_when_the_platform_interface_is_wired_or_at_most_one_platform_is_configured(array $platformServiceIds, ?string $platformInterfaceTarget): void
    {
        $containerBuilder = $this->containerWithPlatforms($platformServiceIds);
        if (null !== $platformInterfaceTarget) {
            $containerBuilder->setAlias(PlatformInterface::class, $platformInterfaceTarget);
        }

        (new UnselectedPlatformsPass(PlatformInterface::class))->process($containerBuilder);

        self::assertSame([], $containerBuilder->getParameter(UnselectedPlatformsPass::PARAMETER));
    }

    /** @return iterable<string, array{list<string>, ?string}> */
    public static function selectedOrSinglePlatformCases(): iterable
    {
        yield 'no platform' => [[], null];
        yield 'a single platform the bundle did not alias' => [['ai.platform.anthropic'], null];
        yield 'two platforms, one aliased by the application' => [['ai.platform.anthropic', 'ai.platform.openai'], 'ai.platform.openai'];
    }

    public function test_it_publishes_no_platform_when_the_application_registers_the_platform_interface_as_a_service(): void
    {
        $containerBuilder = $this->containerWithPlatforms(['ai.platform.anthropic', 'ai.platform.openai']);
        $containerBuilder->register(PlatformInterface::class);

        (new UnselectedPlatformsPass(PlatformInterface::class))->process($containerBuilder);

        self::assertSame([], $containerBuilder->getParameter(UnselectedPlatformsPass::PARAMETER));
    }

    /**
     * @param list<string> $platformServiceIds
     */
    private function containerWithPlatforms(array $platformServiceIds): ContainerBuilder
    {
        $containerBuilder = new ContainerBuilder();
        foreach ($platformServiceIds as $platformServiceId) {
            $containerBuilder->register($platformServiceId)->addTag('ai.platform');
        }

        return $containerBuilder;
    }
}
