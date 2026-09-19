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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OptionalApiKeyPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommandInput;

final class OptionalApiKeyPlatformsTest extends TestCase
{
    #[DataProvider('platformCases')]
    public function test_it_answers_whether_a_platform_can_be_written_without_a_credential(string $provider, bool $expected): void
    {
        self::assertSame($expected, OptionalApiKeyPlatforms::accept(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function platformCases(): iterable
    {
        yield 'a local platform needs none' => ['ollama', true];
        yield 'a gateway may still want one, but the schema does not insist' => ['generic.my_gateway', true];
        yield 'the instance name never decides' => ['anthropic.ollama', false];
        yield 'a hosted platform insists on one' => ['anthropic', false];
        yield 'a platform carrying a default endpoint can still insist' => ['minimax', false];
    }

    public function test_the_no_api_key_option_help_names_every_platform_it_accepts(): void
    {
        $option = (new ReflectionProperty(InitCommandInput::class, 'noApiKey'))->getAttributes(Option::class)[0]->newInstance();
        $description = $option->description;

        self::assertSame(
            OptionalApiKeyPlatforms::NAMES,
            array_values(array_filter(OptionalApiKeyPlatforms::NAMES, static fn (string $platform): bool => str_contains($description, $platform))),
        );
    }
}
