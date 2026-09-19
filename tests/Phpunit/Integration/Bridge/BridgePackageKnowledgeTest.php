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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Finder\Finder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;

/**
 * `ComposerBridgeInstaller` derives a bridge package name from the platform key,
 * hyphenating the ones `symfony/ai-bundle` spells differently. A wrong slug
 * fails only at `composer require`, on the user's machine, so every name `init`
 * could ask for is checked against the packages the bundle itself declares.
 */
final class BridgePackageKnowledgeTest extends TestCase
{
    private const string PLATFORM_CONFIG_DIRECTORY = __DIR__.'/../../../../vendor/symfony/ai-bundle/config/platform';

    private const string BUNDLE_MANIFEST = __DIR__.'/../../../../vendor/symfony/ai-bundle/composer.json';

    public function test_every_platform_asks_for_the_package_the_bundle_declares_for_it(): void
    {
        $declared = $this->packagesTheBundleDeclaresByPlatform();

        $asked = [];
        $expected = [];

        foreach ($this->platformNames() as $platform) {
            $asked[$platform] = ComposerBridgeInstaller::packageFor($platform);
            $expected[$platform] = $declared[$platform] ?? null;
        }

        self::assertSame($expected, $asked);
    }

    /**
     * @return list<string>
     */
    private function platformNames(): array
    {
        $names = [];

        foreach ((new Finder())->files()->in(self::PLATFORM_CONFIG_DIRECTORY)->name('*.php')->depth(0) as $finder) {
            $names[] = $finder->getBasename('.php');
        }

        sort($names);

        self::assertNotSame([], $names, 'The bundle declares at least one platform');

        return $names;
    }

    /**
     * The bundle names each bridge with the platform key hyphenated, so
     * `symfony/ai-open-ai-platform` belongs to `openai`. Keying the declared
     * packages that way pairs each platform with its own package, rather than
     * only asking whether the requested name exists somewhere in the list — a
     * slug pointing at another platform's real bridge would pass that.
     *
     * @return array<string, string>
     */
    private function packagesTheBundleDeclaresByPlatform(): array
    {
        $manifest = file_get_contents(self::BUNDLE_MANIFEST);
        self::assertNotFalse($manifest);

        preg_match_all('#"symfony/ai-([a-z-]+)-platform"#', $manifest, $matches);

        $byPlatform = [];

        foreach (array_unique($matches[1]) as $slug) {
            $byPlatform[str_replace('-', '', $slug)] = \sprintf('symfony/ai-%s-platform', $slug);
        }

        self::assertNotSame([], $byPlatform, 'The bundle declares at least one bridge package');

        return $byPlatform;
    }
}
