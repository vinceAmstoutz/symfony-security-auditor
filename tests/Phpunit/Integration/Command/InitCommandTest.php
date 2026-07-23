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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\RecordingBridgeInstaller;

final class InitCommandTest extends TestCase
{
    private string $configHome;

    private string $dataHome;

    private RecordingBridgeInstaller $recordingBridgeInstaller;

    #[Override]
    protected function setUp(): void
    {
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-init-config-'.$suffix;
        $this->dataHome = sys_get_temp_dir().'/ssa-init-data-'.$suffix;
        $this->recordingBridgeInstaller = new RecordingBridgeInstaller();
    }

    #[Override]
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

    public function test_it_strips_invalid_characters_when_deriving_the_api_key_variable_from_the_provider(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['my-ai', 'my-model', '']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'my-ai', 'platform' => ['my-ai' => ['api_key' => '%env(MYAI_API_KEY)%']], 'model' => 'my-model'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_folds_a_bridge_package_slug_to_the_platform_config_key(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'open-ai', '--model' => 'gpt-5.4'],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_installs_the_bridge_under_the_normalized_provider_key(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'Open-AI', '--model' => 'gpt-5.4'],
            ['interactive' => false],
        );

        self::assertSame([['openai', $this->dataHome.'/symfony-security-auditor']], $this->recordingBridgeInstaller->installations);
    }

    public function test_it_uses_the_provider_model_and_env_var_options_without_prompting(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => 'MY_CUSTOM_KEY'],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(MY_CUSTOM_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_derives_the_api_key_variable_from_the_provider_option_when_env_var_is_omitted(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'openai', '--model' => 'gpt-5.4'],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_installs_the_bridge_for_the_provider_option(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => 'MY_CUSTOM_KEY'],
            ['interactive' => false],
        );

        self::assertSame([['openai', $this->dataHome.'/symfony-security-auditor']], $this->recordingBridgeInstaller->installations);
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

    public function test_it_overwrites_an_existing_configuration_with_force_without_asking(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'openai', '--model' => 'gpt-5.4', '--force' => true],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_skips_the_overwrite_confirmation_when_forced(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        $commandTester->execute(['--force' => true]);

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_points_at_force_when_the_overwrite_is_declined(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['no']);

        $commandTester->execute([]);

        self::assertStringContainsString('--force', $commandTester->getDisplay());
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

    public function test_it_confirms_where_the_configuration_was_written(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        $commandTester->execute([]);

        self::assertStringContainsString('Configuration written to', $commandTester->getDisplay());
    }

    public function test_it_treats_an_empty_answer_as_declining_the_overwrite(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['']);

        $commandTester->execute([]);

        self::assertSame(['model' => 'keep-me'], Yaml::parseFile($this->configFile()));
    }

    public function test_it_warns_when_it_leaves_the_existing_configuration_untouched(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['no']);

        $commandTester->execute([]);

        self::assertStringContainsString('Aborted', $commandTester->getDisplay());
    }

    private function commandTester(): CommandTester
    {
        $initCommand = new InitCommand(
            new XdgConfigPathResolver($this->configHome, null, null, $this->dataHome),
            new StandaloneConfigFactory(),
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
