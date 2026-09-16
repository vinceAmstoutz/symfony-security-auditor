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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Bridge;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

final class ProviderKeyTest extends TestCase
{
    #[DataProvider('providerCases')]
    public function test_it_splits_a_provider_into_its_platform_and_instance(string $provider, string $expectedPlatform, ?string $expectedInstance): void
    {
        $providerKey = ProviderKey::of($provider);

        self::assertSame(
            [$expectedPlatform, $expectedInstance],
            [$providerKey->platform, $providerKey->instance],
        );
    }

    /**
     * @return iterable<string, array{string, string, string|null}>
     */
    public static function providerCases(): iterable
    {
        yield 'a flat platform has no instance' => ['anthropic', 'anthropic', null];
        yield 'an instance-keyed platform splits on the first dot' => ['generic.my_gateway', 'generic', 'my_gateway'];
        yield 'only the first dot separates, the rest belongs to the instance' => ['generic.eu.gateway', 'generic', 'eu.gateway'];
        yield 'a trailing dot names no instance' => ['generic.', 'generic', null];
    }
}
