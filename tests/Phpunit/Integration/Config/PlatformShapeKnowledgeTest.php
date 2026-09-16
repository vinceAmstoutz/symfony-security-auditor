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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Finder\Finder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatforms;

/**
 * `BaseUrlPlatforms` and `HandWrittenPlatforms` restate what `symfony/ai-bundle`
 * declares about each platform's connection block. A bundle upgrade that adds a
 * platform, or gives an existing one a `base_url`, would otherwise leave them
 * quietly wrong: `init` would stop asking for a key it now needs, or keep
 * refusing a platform it could write. Reading the bundle's own definitions back
 * turns that into a failing test.
 */
final class PlatformShapeKnowledgeTest extends TestCase
{
    private const string PLATFORM_CONFIG_GLOB = __DIR__.'/../../../../vendor/symfony/ai-bundle/config/platform';

    public function test_every_platform_declaring_a_base_url_is_named(): void
    {
        self::assertSame(BaseUrlPlatforms::NAMES, $this->platformsDeclaring('base_url'));
    }

    public function test_no_platform_is_named_twice_as_writable_and_hand_written(): void
    {
        self::assertSame(
            ['azure'],
            array_values(array_intersect(BaseUrlPlatforms::NAMES, array_keys(HandWrittenPlatforms::REQUIREMENTS))),
        );
    }

    public function test_every_hand_written_platform_still_exists_in_the_bundle(): void
    {
        self::assertSame([], array_diff(array_keys(HandWrittenPlatforms::REQUIREMENTS), $this->platformNames()));
    }

    public function test_no_platform_without_an_api_key_node_is_left_writable(): void
    {
        $withoutApiKey = array_values(array_diff($this->platformNames(), $this->platformsDeclaring('api_key')));

        self::assertSame([], array_diff($withoutApiKey, array_keys(HandWrittenPlatforms::REQUIREMENTS)));
    }

    /**
     * @return list<string>
     */
    private function platformNames(): array
    {
        $names = [];

        foreach ($this->configFiles() as $finder) {
            $names[] = $finder->getBasename('.php');
        }

        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    private function platformsDeclaring(string $node): array
    {
        $names = [];
        $pattern = \sprintf('/(?:string|scalar)Node\(\x27%s\x27\)/', preg_quote($node, '/'));

        foreach ($this->configFiles() as $finder) {
            if (1 === preg_match($pattern, $finder->getContents())) {
                $names[] = $finder->getBasename('.php');
            }
        }

        sort($names);

        return $names;
    }

    private function configFiles(): Finder
    {
        return (new Finder())->files()->in(self::PLATFORM_CONFIG_GLOB)->name('*.php')->depth(0);
    }
}
