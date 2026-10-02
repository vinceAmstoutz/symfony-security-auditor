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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BundledAiPlatformVersion;

final class BundledAiPlatformVersionTest extends TestCase
{
    public function test_it_reads_the_release_this_package_was_installed_with(): void
    {
        self::assertSame('v0.14.1', BundledAiPlatformVersion::detect([
            $this->bridgeTree('v0.15.0'),
            $this->ownTree('v0.14.1'),
        ]));
    }

    public function test_it_ignores_the_bridge_tree_even_when_it_is_registered_first(): void
    {
        self::assertNull(BundledAiPlatformVersion::detect([$this->bridgeTree('v0.15.0')]));
    }

    #[DataProvider('versionsThatAreNotReleases')]
    public function test_it_pins_nothing_outside_a_tagged_release(string $version): void
    {
        self::assertNull(BundledAiPlatformVersion::detect([$this->ownTree($version)]));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function versionsThatAreNotReleases(): iterable
    {
        yield 'branch alias' => ['0.14.x-dev'];
        yield 'dev branch' => ['dev-main'];
        yield 'pre-release' => ['v0.15.0-BETA1'];
    }

    public function test_it_pins_nothing_when_the_package_is_not_installed_in_its_own_tree(): void
    {
        self::assertNull(BundledAiPlatformVersion::detect([['root' => ['name' => 'vinceamstoutz/symfony-security-auditor'], 'versions' => []]]));
        self::assertNull(BundledAiPlatformVersion::detect([['root' => ['name' => 'vinceamstoutz/symfony-security-auditor']]]));
        self::assertNull(BundledAiPlatformVersion::detect([['root' => 'not-an-array']]));
    }

    public function test_the_running_checkout_reports_a_release_or_nothing(): void
    {
        $version = BundledAiPlatformVersion::detect();

        self::assertTrue(null === $version || 1 === preg_match('/^v?\d+\.\d+\.\d+$/', $version), \sprintf('Unexpected bundled version "%s".', $version ?? 'null'));
    }

    /**
     * @return array<string, mixed>
     */
    private function ownTree(string $aiPlatformVersion): array
    {
        return [
            'root' => ['name' => 'vinceamstoutz/symfony-security-auditor'],
            'versions' => ['symfony/ai-platform' => ['pretty_version' => $aiPlatformVersion]],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function bridgeTree(string $aiPlatformVersion): array
    {
        return [
            'root' => ['name' => '__root__'],
            'versions' => ['symfony/ai-platform' => ['pretty_version' => $aiPlatformVersion]],
        ];
    }
}
