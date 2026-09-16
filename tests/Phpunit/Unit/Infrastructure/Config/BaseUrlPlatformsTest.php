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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;

final class BaseUrlPlatformsTest extends TestCase
{
    #[DataProvider('platformCases')]
    public function test_it_answers_whether_a_platform_declares_a_base_url(string $provider, bool $expected): void
    {
        self::assertSame($expected, BaseUrlPlatforms::accept(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function platformCases(): iterable
    {
        yield 'a flat platform requiring a base_url' => ['albert', true];
        yield 'the other flat platform requiring a base_url' => ['amazeeai', true];
        yield 'an instance-keyed platform exposing one' => ['generic.my_gateway', true];
        yield 'an instance-keyed platform exposing one beside other required fields' => ['azure.prod', true];
        yield 'the instance name never decides' => ['openresponses.my_gateway', true];
        yield 'an instance-keyed platform without one' => ['bedrock.default', false];
        yield 'a flat platform naming its endpoint differently' => ['ollama', false];
        yield 'a flat platform hosting no endpoint' => ['anthropic', false];
    }
}
