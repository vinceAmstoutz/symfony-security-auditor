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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\RecordingBridgeInstaller;

final class StandaloneInitEndToEndTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    private string $dataHome;

    private RecordingBridgeInstaller $recordingBridgeInstaller;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-init-config-'.$suffix;
        $this->dataHome = sys_get_temp_dir().'/ssa-init-data-'.$suffix;
        $this->recordingBridgeInstaller = new RecordingBridgeInstaller();
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->configHome, $this->dataHome]);
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    public function test_the_standalone_init_command_writes_the_config_and_installs_the_chosen_bridge(): void
    {
        $commandTester = $this->initCommandTester();
        $commandTester->setInputs(['openai', 'gpt-5', 'OPENAI_API_KEY']);

        $exitCode = $commandTester->execute([]);

        self::assertSame(0, $exitCode);

        $configFile = $this->configHome.'/symfony-security-auditor/config.yaml';
        self::assertFileExists($configFile);
        $config = (string) file_get_contents($configFile);
        self::assertStringContainsString('openai', $config);
        self::assertStringContainsString('%env(OPENAI_API_KEY)%', $config);
        self::assertStringContainsString('gpt-5', $config);

        self::assertSame(
            [['openai', $this->dataHome.'/symfony-security-auditor']],
            $this->recordingBridgeInstaller->installations,
        );
    }

    private function initCommandTester(): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null, $this->dataHome);

        $application = (new StandaloneApplicationFactory(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver()),
            $xdgConfigPathResolver,
            bridgeInstaller: $this->recordingBridgeInstaller,
        ))->create();

        return new CommandTester($application->find(InitCommand::NAME));
    }
}
