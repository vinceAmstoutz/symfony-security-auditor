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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\GitHubBinaryAsset;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\GitHubBinaryAssetResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ReleaseClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\RunningBinaryLocatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdater;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate\Fixture\FakeReleaseClient;

final class SelfUpdaterTest extends TestCase
{
    private const string LATEST_RELEASE_API_URL = 'https://api.github.com/repos/vinceAmstoutz/symfony-security-auditor/releases/latest';

    private string $workingDirectory;

    private string $binaryPath;

    #[Override]
    protected function setUp(): void
    {
        $this->workingDirectory = sys_get_temp_dir().'/ssa-updater-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->workingDirectory);
        $this->binaryPath = $this->workingDirectory.'/symfony-security-auditor';
        (new Filesystem())->dumpFile($this->binaryPath, 'OLD-BINARY');
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->workingDirectory);
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function test_it_downloads_verifies_and_replaces_the_binary_with_the_latest_release(): void
    {
        $payload = 'NEW-BINARY';
        $selfUpdateResult = $this->selfUpdater($this->clientFor('9.9.9', $payload, hash('sha256', $payload)))->run('1.0.0', false);

        self::assertSame(SelfUpdateStatus::Updated, $selfUpdateResult->status);
        self::assertStringEqualsFile($this->binaryPath, $payload);
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function test_it_marks_the_replaced_binary_as_executable(): void
    {
        $payload = 'NEW-BINARY';
        $this->selfUpdater($this->clientFor('9.9.9', $payload, hash('sha256', $payload)))->run('1.0.0', false);

        self::assertSame(0o755, fileperms($this->binaryPath) & 0o777);
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function test_it_reports_already_up_to_date_without_touching_the_binary(): void
    {
        $selfUpdateResult = $this->selfUpdater($this->clientFor('1.0.0', 'IGNORED', hash('sha256', 'IGNORED')))->run('1.0.0', false);

        self::assertSame(SelfUpdateStatus::AlreadyUpToDate, $selfUpdateResult->status);
        self::assertStringEqualsFile($this->binaryPath, 'OLD-BINARY');
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function test_check_only_reports_an_available_update_without_touching_the_binary(): void
    {
        $selfUpdateResult = $this->selfUpdater($this->clientFor('9.9.9', 'NEW', hash('sha256', 'NEW')))->run('1.0.0', true);

        self::assertSame(SelfUpdateStatus::UpdateAvailable, $selfUpdateResult->status);
        self::assertStringEqualsFile($this->binaryPath, 'OLD-BINARY');
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function test_it_rejects_a_download_whose_checksum_does_not_match(): void
    {
        $selfUpdater = $this->selfUpdater($this->clientFor('9.9.9', 'NEW', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'));

        try {
            $this->expectException(SelfUpdateFailedException::class);

            $selfUpdater->run('1.0.0', false);
        } finally {
            self::assertStringEqualsFile($this->binaryPath, 'OLD-BINARY');
            self::assertCount(0, (new Finder())->in($this->workingDirectory)->files()->name('/\.download$/')->ignoreDotFiles(false));
        }
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function test_it_refuses_to_update_when_the_binary_is_not_writable(): void
    {
        $selfUpdater = $this->selfUpdater($this->clientFor('9.9.9', 'NEW', hash('sha256', 'NEW')), $this->workingDirectory.'/missing/symfony-security-auditor');

        $this->expectException(SelfUpdateFailedException::class);
        $this->expectExceptionMessage('not writable');

        $selfUpdater->run('1.0.0', false);
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function test_it_wraps_a_replacement_io_failure(): void
    {
        $filesystem = new class extends Filesystem {
            #[Override]
            public function rename(string $origin, string $target, bool $overwrite = false): void
            {
                throw new IOException('rename refused');
            }
        };
        $payload = 'NEW';
        $selfUpdater = $this->selfUpdater($this->clientFor('9.9.9', $payload, hash('sha256', $payload)), $this->binaryPath, $filesystem);

        try {
            $this->expectException(SelfUpdateFailedException::class);

            $selfUpdater->run('1.0.0', false);
        } finally {
            self::assertCount(0, (new Finder())->in($this->workingDirectory)->files()->name('/\.download$/')->ignoreDotFiles(false));
        }
    }

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    #[DataProvider('unresolvableLatestVersionPayloads')]
    public function test_it_rejects_an_unresolvable_latest_version(string $apiBody): void
    {
        $selfUpdater = $this->selfUpdater(new FakeReleaseClient([self::LATEST_RELEASE_API_URL => $apiBody]));

        $this->expectException(SelfUpdateFailedException::class);

        $selfUpdater->run('1.0.0', false);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unresolvableLatestVersionPayloads(): iterable
    {
        yield 'not json' => ['this is not json'];
        yield 'json scalar' => ['123'];
        yield 'object without tag_name' => ['{"foo":"bar"}'];
        yield 'non-string tag_name' => ['{"tag_name":123}'];
        yield 'empty tag_name' => ['{"tag_name":""}'];
    }

    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    private function clientFor(string $tagName, string $payload, string $checksum): FakeReleaseClient
    {
        $asset = $this->asset($tagName);

        return new FakeReleaseClient([
            self::LATEST_RELEASE_API_URL => \sprintf('{"tag_name":"%s"}', $tagName),
            $asset->checksumUrl => \sprintf("%s\n", $checksum),
        ], $payload);
    }

    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    private function asset(string $version): GitHubBinaryAsset
    {
        return (new GitHubBinaryAssetResolver('Linux', 'x86_64'))->resolve($version);
    }

    private function selfUpdater(ReleaseClientInterface $releaseClient, ?string $binaryPath = null, ?Filesystem $filesystem = null): SelfUpdater
    {
        $locator = self::createStub(RunningBinaryLocatorInterface::class);
        $locator->method('path')->willReturn($binaryPath ?? $this->binaryPath);

        return new SelfUpdater($releaseClient, new GitHubBinaryAssetResolver('Linux', 'x86_64'), $locator, $filesystem ?? new Filesystem());
    }
}
