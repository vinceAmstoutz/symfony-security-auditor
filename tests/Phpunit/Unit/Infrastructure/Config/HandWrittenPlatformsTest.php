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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatforms;

final class HandWrittenPlatformsTest extends TestCase
{
    #[DataProvider('platformCases')]
    public function test_it_reports_what_a_platform_needs_beyond_an_api_key(string $provider, ?string $expected): void
    {
        self::assertSame($expected, HandWrittenPlatforms::requirementOf(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function platformCases(): iterable
    {
        yield 'an instance-keyed platform needing a deployment' => ['azure.prod', 'a "deployment" name beside the api_key'];
        yield 'an instance-keyed platform taking a runtime client' => ['bedrock.prod', 'a "bedrock_runtime_client" service rather than an api_key'];
        yield 'an instance-keyed platform wrapping another' => ['cache.prod', 'the "platform" it wraps rather than an api_key'];
        yield 'an instance-keyed platform listing its fallbacks' => ['failover.prod', 'the list of "platforms" it falls back through rather than an api_key'];
        yield 'a flat platform needing a version' => ['cartesia', 'a "version" beside the api_key'];
        yield 'a flat platform addressed by host url' => ['lmstudio', 'a "host_url" rather than an api_key'];
        yield 'the other flat platform addressed by host url' => ['dockermodelrunner', 'a "host_url" rather than an api_key'];
        yield 'a flat platform taking no options' => ['transformersphp', 'an empty connection block rather than an api_key'];
        yield 'a platform init writes in full' => ['anthropic', null];
        yield 'an instance-keyed platform init writes in full' => ['generic.my_gateway', null];
    }
}
