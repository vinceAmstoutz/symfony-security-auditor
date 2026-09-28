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
use ReflectionProperty;
use Symfony\Component\Console\Attribute\Option;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EndpointPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommandInput;

final class EndpointPlatformsTest extends TestCase
{
    #[DataProvider('platformCases')]
    public function test_it_answers_whether_a_platform_declares_an_endpoint(string $provider, bool $expected): void
    {
        self::assertSame($expected, EndpointPlatforms::accept(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function platformCases(): iterable
    {
        yield 'the platform hosting no default endpoint' => ['ollama', true];
        yield 'a platform carrying a default endpoint' => ['deepgram', true];
        yield 'another platform carrying a default endpoint' => ['minimax', true];
        yield 'a platform naming the same thing base_url' => ['generic.my_gateway', false];
        yield 'the instance name never decides' => ['generic.ollama', false];
        yield 'a platform hosting no endpoint at all' => ['anthropic', false];
    }

    #[DataProvider('requirementCases')]
    public function test_it_answers_whether_the_endpoint_has_to_be_supplied(string $provider, bool $expected): void
    {
        self::assertSame($expected, EndpointPlatforms::requires(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function requirementCases(): iterable
    {
        yield 'the platform declaring no default has to be told where to go' => ['ollama', true];
        yield 'a platform carrying a default does not' => ['deepgram', false];
        yield 'a platform hosting no endpoint at all does not' => ['anthropic', false];
    }

    public function test_the_endpoint_option_help_names_every_platform_it_accepts(): void
    {
        $option = (new ReflectionProperty(InitCommandInput::class, 'endpoint'))->getAttributes(Option::class)[0]->newInstance();
        $description = $option->description;

        self::assertSame(
            EndpointPlatforms::NAMES,
            array_values(array_filter(EndpointPlatforms::NAMES, static fn (string $platform): bool => str_contains($description, $platform))),
        );
    }
}
