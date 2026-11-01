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

final class ComposerPharTest extends TestCase
{
    private const string PAYLOAD = '<?php // composer';

    private const string FIXTURE_PHAR = __DIR__.'/../../../Fixture/Composer/composer.phar';

    private Filesystem $filesystem;

    private string $directory;

    private string $bundledPhar;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->directory = sys_get_temp_dir().'/ssa-composer-phar-'.bin2hex(random_bytes(6));
        $this->bundledPhar = $this->directory.'/bundled/composer.phar';

        $this->filesystem->dumpFile($this->bundledPhar, self::PAYLOAD);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->directory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_unpacks_the_composer_the_binary_bundles_so_it_runs_outside_a_phar(): void
    {
        $composerPhar = new ComposerPhar(self::FIXTURE_PHAR, (string) hash_file('sha256', self::FIXTURE_PHAR));

        self::assertStringEqualsFile($composerPhar->in($this->directory.'/.composer'), "<?php echo \"fixture composer\";\n");
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_replaces_the_composer_an_earlier_release_copied(): void
    {
        $this->filesystem->dumpFile($this->directory.'/.composer/composer.phar', '<?php // an older composer');
        $this->filesystem->dumpFile($this->directory.'/.composer/composer/bin/composer', '<?php // an older composer');

        $composerPhar = new ComposerPhar(self::FIXTURE_PHAR, (string) hash_file('sha256', self::FIXTURE_PHAR));

        self::assertStringEqualsFile($composerPhar->in($this->directory.'/.composer'), "<?php echo \"fixture composer\";\n");
    }

    public function test_it_refuses_a_bundled_composer_whose_checksum_does_not_match_and_keeps_none_of_it(): void
    {
        $composerPhar = new ComposerPhar($this->bundledPhar, hash('sha256', 'another composer'));

        try {
            $composerPhar->in($this->directory.'/.composer');
            self::fail('A tampered composer.phar was accepted.');
        } catch (BridgeInstallationFailedException $bridgeInstallationFailedException) {
            self::assertSame([], glob($this->directory.'/.composer/*'), $bridgeInstallationFailedException->getMessage());
        }
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_reports_a_build_that_bundles_no_composer_as_a_failed_bridge_installation(): void
    {
        $this->expectExceptionMessage('This build bundles no composer.phar 2.8.12');

        (new ComposerPhar($this->directory.'/absent/composer.phar'))->in($this->directory.'/.composer');
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_reports_a_directory_it_cannot_write_composer_to_as_a_failed_bridge_installation(): void
    {
        $this->filesystem->dumpFile($this->directory.'/a-file', '');

        $this->expectExceptionMessage(\sprintf('Could not copy composer.phar 2.8.12 to "%s/a-file/.composer"', $this->directory));

        (new ComposerPhar($this->bundledPhar, hash('sha256', self::PAYLOAD)))->in($this->directory.'/a-file/.composer');
    }

    public function test_the_composer_a_release_bundles_sits_in_the_resources_of_the_package(): void
    {
        self::assertSame(\dirname(__DIR__, 4).'/resources/composer.phar', ComposerPhar::bundledPath());
    }
}
