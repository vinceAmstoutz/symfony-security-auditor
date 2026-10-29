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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerPhar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge\Fixture\ComposerPharReleaseClient;

final class ComposerPharTest extends TestCase
{
    private const string PAYLOAD = '<?php // composer';

    private Filesystem $filesystem;

    private string $directory;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->directory = sys_get_temp_dir().'/ssa-composer-phar-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->directory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_downloads_composer_into_the_directory(): void
    {
        $composerPhar = new ComposerPhar(new ComposerPharReleaseClient(self::PAYLOAD), sha256: hash('sha256', self::PAYLOAD));

        self::assertStringEqualsFile($composerPhar->in($this->directory), self::PAYLOAD);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_reuses_the_composer_it_downloaded_before(): void
    {
        $composerPharReleaseClient = new ComposerPharReleaseClient(self::PAYLOAD);
        $composerPhar = new ComposerPhar($composerPharReleaseClient, sha256: hash('sha256', self::PAYLOAD));

        $composerPhar->in($this->directory);
        $composerPhar->in($this->directory);

        self::assertSame(['https://getcomposer.org/download/2.8.12/composer.phar'], $composerPharReleaseClient->downloadedUrls);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_replaces_a_composer_that_is_not_the_pinned_release(): void
    {
        $this->filesystem->dumpFile($this->directory.'/composer.phar', '<?php // an older composer');
        $composerPhar = new ComposerPhar(new ComposerPharReleaseClient(self::PAYLOAD), sha256: hash('sha256', self::PAYLOAD));

        self::assertStringEqualsFile($composerPhar->in($this->directory), self::PAYLOAD);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_reports_a_download_that_failed_as_a_failed_bridge_installation(): void
    {
        $this->expectException(BridgeInstallationFailedException::class);

        (new ComposerPhar(new ComposerPharReleaseClient(null)))->in($this->directory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_reports_a_directory_it_cannot_create_as_a_failed_bridge_installation(): void
    {
        $this->filesystem->dumpFile($this->directory.'/a-file', '');

        $this->expectException(BridgeInstallationFailedException::class);

        (new ComposerPhar(new ComposerPharReleaseClient(self::PAYLOAD)))->in($this->directory.'/a-file/.composer');
    }

    public function test_it_refuses_a_download_whose_checksum_does_not_match_and_keeps_none_of_it(): void
    {
        $composerPhar = new ComposerPhar(new ComposerPharReleaseClient(self::PAYLOAD), sha256: hash('sha256', 'another composer'));

        try {
            $composerPhar->in($this->directory);
            self::fail('A tampered composer.phar was accepted.');
        } catch (BridgeInstallationFailedException $bridgeInstallationFailedException) {
            self::assertSame([], glob($this->directory.'/*'), $bridgeInstallationFailedException->getMessage());
        }
    }
}
