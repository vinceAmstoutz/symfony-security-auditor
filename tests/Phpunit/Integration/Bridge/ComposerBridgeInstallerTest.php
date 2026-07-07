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

use Closure;
use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;

final class ComposerBridgeInstallerTest extends TestCase
{
    private string $targetDirectory;

    private Filesystem $filesystem;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->targetDirectory = sys_get_temp_dir().'/ssa-bridge-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_initialises_the_target_directory_as_a_composer_project(): void
    {
        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $this->targetDirectory);

        self::assertSame("{}\n", file_get_contents($this->targetDirectory.'/composer.json'));
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_wraps_a_manifest_write_io_failure_as_a_bridge_installation_failed_exception(): void
    {
        $blockingFile = $this->targetDirectory.'/not-a-directory';
        $this->filesystem->dumpFile($blockingFile, 'x');

        $this->expectException(BridgeInstallationFailedException::class);

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $blockingFile);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_preserves_an_existing_composer_manifest(): void
    {
        $this->filesystem->dumpFile($this->targetDirectory.'/composer.json', '{"name":"acme/app"}');

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $this->targetDirectory);

        self::assertSame('{"name":"acme/app"}', file_get_contents($this->targetDirectory.'/composer.json'));
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_requires_the_provider_specific_bridge_package(): void
    {
        $captured = [];
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static function (string $package, string $targetDirectory) use (&$captured): Process {
            $captured[] = $package;

            return new Process(['true']);
        });

        $composerBridgeInstaller->install('gemini', $this->targetDirectory);

        self::assertSame(['symfony/ai-gemini-platform'], $captured);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_throws_when_the_install_process_fails(): void
    {
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static fn (string $package, string $targetDirectory): Process => new Process(['false']));

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('symfony/ai-anthropic-platform');

        $composerBridgeInstaller->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_the_failure_message_carries_the_composer_error_output(): void
    {
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static fn (string $package, string $targetDirectory): Process => Process::fromShellCommandline('echo "network unreachable" 1>&2; exit 1'));

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('network unreachable');

        $composerBridgeInstaller->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_throws_when_composer_cannot_be_started(): void
    {
        $unlaunchableWorkingDirectory = $this->targetDirectory.'/missing-'.bin2hex(random_bytes(4));
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static fn (string $package, string $targetDirectory): Process => new Process(['true'], $unlaunchableWorkingDirectory));

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('composer');

        $composerBridgeInstaller->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_default_process_builder_uses_composer_require_in_the_target_directory(): void
    {
        $process = (ComposerBridgeInstaller::defaultProcessBuilder())('symfony/ai-anthropic-platform', '/data/bridges');

        $commandLine = $process->getCommandLine();
        self::assertStringContainsString("'composer'", $commandLine);
        self::assertStringContainsString("'require'", $commandLine);
        self::assertStringContainsString("'symfony/ai-anthropic-platform'", $commandLine);
        self::assertStringContainsString("'--working-dir=/data/bridges'", $commandLine);
        self::assertStringContainsString("'--no-interaction'", $commandLine);
        self::assertNull($process->getTimeout());
    }

    /**
     * @return Closure(string, string): Process
     */
    private function succeedingProcess(): Closure
    {
        return static fn (string $package, string $targetDirectory): Process => new Process(['true']);
    }
}
