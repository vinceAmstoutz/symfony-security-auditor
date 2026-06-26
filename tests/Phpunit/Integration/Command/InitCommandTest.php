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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\RecordingBridgeInstaller;

final class InitCommandTest extends TestCase
{
    private string $configHome;

    private string $dataHome;

    private RecordingBridgeInstaller $recordingBridgeInstaller;

    protected function setUp(): void
    {
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-init-config-'.$suffix;
        $this->dataHome = sys_get_temp_dir().'/ssa-init-data-'.$suffix;
        $this->recordingBridgeInstaller = new RecordingBridgeInstaller();
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove([$this->configHome, $this->dataHome]);
    }

    public function test_it_writes_the_configuration_for_the_chosen_provider(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_installs_the_bridge_for_the_chosen_provider_in_the_data_directory(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        $commandTester->execute([]);

        self::assertSame([['openai', $this->dataHome.'/symfony-security-auditor']], $this->recordingBridgeInstaller->installations);
    }

    public function test_it_derives_the_api_key_variable_from_the_provider_name_by_default(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['gemini', 'gemini-2.5-pro', '']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'gemini', 'platform' => ['gemini' => ['api_key' => '%env(GEMINI_API_KEY)%']], 'model' => 'gemini-2.5-pro'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_leaves_an_existing_configuration_untouched_when_the_overwrite_is_declined(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['no']);

        $commandTester->execute([]);

        self::assertSame(['model' => 'keep-me'], Yaml::parseFile($this->configFile()));
    }

    public function test_it_does_not_install_a_bridge_when_the_overwrite_is_declined(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['no']);

        $commandTester->execute([]);

        self::assertSame([], $this->recordingBridgeInstaller->installations);
    }

    public function test_it_overwrites_an_existing_configuration_when_confirmed(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['yes', 'openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_reports_success(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));
    }

    private function commandTester(): CommandTester
    {
        $initCommand = new InitCommand(
            new XdgConfigPathResolver($this->configHome, null, null, $this->dataHome),
            new YamlStandaloneConfigWriter(),
            $this->recordingBridgeInstaller,
        );

        return new CommandTester($initCommand);
    }

    private function configFile(): string
    {
        return $this->configHome.'/symfony-security-auditor/config.yaml';
    }
}
