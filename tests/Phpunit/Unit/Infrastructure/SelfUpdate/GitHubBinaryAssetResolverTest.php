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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\GitHubBinaryAssetResolver;

final class GitHubBinaryAssetResolverTest extends TestCase
{
    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    #[DataProvider('platformCases')]
    public function test_it_resolves_the_release_asset_and_urls_for_the_platform(string $osFamily, string $machine, string $expectedAsset): void
    {
        $gitHubBinaryAsset = (new GitHubBinaryAssetResolver($osFamily, $machine))->resolve('1.2.3');

        self::assertSame($expectedAsset, $gitHubBinaryAsset->name);
        self::assertSame('https://github.com/vinceAmstoutz/symfony-security-auditor/releases/download/1.2.3/'.$expectedAsset, $gitHubBinaryAsset->downloadUrl);
        self::assertSame($gitHubBinaryAsset->downloadUrl.'.sha256', $gitHubBinaryAsset->checksumUrl);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function platformCases(): iterable
    {
        yield 'linux x86_64' => ['Linux', 'x86_64', 'symfony-security-auditor-linux-x86_64'];
        yield 'linux amd64' => ['Linux', 'amd64', 'symfony-security-auditor-linux-x86_64'];
        yield 'linux aarch64' => ['Linux', 'aarch64', 'symfony-security-auditor-linux-aarch64'];
        yield 'linux arm64' => ['Linux', 'arm64', 'symfony-security-auditor-linux-aarch64'];
        yield 'macos x86_64' => ['Darwin', 'x86_64', 'symfony-security-auditor-macos-x86_64'];
        yield 'macos arm64' => ['Darwin', 'arm64', 'symfony-security-auditor-macos-arm64'];
        yield 'macos aarch64' => ['Darwin', 'aarch64', 'symfony-security-auditor-macos-arm64'];
    }

    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    #[DataProvider('unsupportedPlatformCases')]
    public function test_it_rejects_an_unsupported_platform(string $osFamily, string $machine): void
    {
        $this->expectException(UnsupportedSelfUpdatePlatformException::class);

        (new GitHubBinaryAssetResolver($osFamily, $machine))->resolve('1.2.3');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unsupportedPlatformCases(): iterable
    {
        yield 'unsupported operating system' => ['Windows', 'x86_64'];
        yield 'unsupported bsd operating system' => ['BSD', 'x86_64'];
        yield 'unsupported architecture' => ['Linux', 'riscv64'];
    }

    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    #[DataProvider('unsupportedPlatformCases')]
    public function test_it_reports_an_unsupported_platform_without_an_asset_lookup(string $osFamily, string $machine): void
    {
        $this->expectException(UnsupportedSelfUpdatePlatformException::class);

        (new GitHubBinaryAssetResolver($osFamily, $machine))->assertSupportedPlatform();
    }
}
