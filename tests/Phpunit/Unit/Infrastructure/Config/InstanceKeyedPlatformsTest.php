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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\InstanceKeyedPlatforms;

final class InstanceKeyedPlatformsTest extends TestCase
{
    #[DataProvider('providerCases')]
    public function test_it_answers_whether_a_provider_still_owes_an_instance(string $provider, bool $expected): void
    {
        self::assertSame($expected, InstanceKeyedPlatforms::needsAnInstance(ProviderKey::of($provider)));
    }

    #[DataProvider('strayInstanceCases')]
    public function test_it_answers_whether_a_provider_names_an_instance_it_may_not(string $provider, bool $expected): void
    {
        self::assertSame($expected, InstanceKeyedPlatforms::rejectsAnInstance(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function strayInstanceCases(): iterable
    {
        yield 'a flat platform given an instance' => ['anthropic.prod', true];
        yield 'a flat platform with a base_url given an instance' => ['albert.prod', true];
        yield 'a flat platform named alone' => ['anthropic', false];
        yield 'an instance-keyed platform naming its instance' => ['generic.my_gateway', false];
        yield 'an instance-keyed platform named alone' => ['generic', false];
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function providerCases(): iterable
    {
        yield 'an instance-keyed platform named alone' => ['generic', true];
        yield 'the other writable instance-keyed platform named alone' => ['openresponses', true];
        yield 'a hand-written instance-keyed platform named alone' => ['azure', true];
        yield 'an instance-keyed platform naming its instance' => ['generic.my_gateway', false];
        yield 'a trailing dot names no instance' => ['generic.', true];
        yield 'a flat platform never owes one' => ['anthropic', false];
        yield 'a flat platform with a base_url never owes one' => ['albert', false];
    }
}
