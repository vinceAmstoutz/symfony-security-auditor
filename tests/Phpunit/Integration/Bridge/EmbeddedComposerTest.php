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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\EmbeddedComposer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\SelfInvocation;

final class EmbeddedComposerTest extends TestCase
{
    private const string FIXTURE_PHAR = __DIR__.'/../../../Fixture/Composer/composer.phar';

    private Filesystem $filesystem;

    private string $directory;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->directory = sys_get_temp_dir().'/ssa-embedded-composer-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->directory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_runs_this_binary_as_composer_with_the_given_arguments(): void
    {
        $process = $this->embeddedComposer()->process($this->directory.'/.composer', ['audit', '--locked']);

        self::assertSame("'/usr/bin/php' '/opt/symfony-security-auditor' 'audit' '--locked'", $process->getCommandLine());
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_the_process_runs_the_composer_the_binary_bundles(): void
    {
        $embeddedComposer = new EmbeddedComposer(
            new SelfInvocation(\dirname(__DIR__, 4).'/bin/symfony-security-auditor', 'cli', \PHP_BINARY),
            new ComposerPhar(self::FIXTURE_PHAR, (string) hash_file('sha256', self::FIXTURE_PHAR)),
        );

        $process = $embeddedComposer->process($this->directory.'/.composer', ['--version']);
        $process->run();

        self::assertSame('fixture composer', $process->getOutput());
    }

    public function test_a_build_bundling_no_composer_phar_has_no_embedded_composer(): void
    {
        self::assertNull(EmbeddedComposer::bundled(new SelfInvocation('/opt/symfony-security-auditor'), new ComposerPhar($this->directory.'/composer.phar')));
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_a_build_bundling_a_composer_phar_runs_it(): void
    {
        $embeddedComposer = EmbeddedComposer::bundled(
            new SelfInvocation(\dirname(__DIR__, 4).'/bin/symfony-security-auditor', 'cli', \PHP_BINARY),
            new ComposerPhar(self::FIXTURE_PHAR, (string) hash_file('sha256', self::FIXTURE_PHAR)),
        );
        self::assertInstanceOf(EmbeddedComposer::class, $embeddedComposer);

        $process = $embeddedComposer->process($this->directory.'/.composer', ['--version']);
        $process->run();

        self::assertSame('fixture composer', $process->getOutput());
    }

    private function embeddedComposer(): EmbeddedComposer
    {
        return new EmbeddedComposer(
            new SelfInvocation('/opt/symfony-security-auditor', 'cli', '/usr/bin/php'),
            new ComposerPhar(self::FIXTURE_PHAR, (string) hash_file('sha256', self::FIXTURE_PHAR)),
        );
    }
}
