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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FilesystemCredentialStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\FailingBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\RecordingBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\UnhideableCredentialPrompt;

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
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_installs_the_bridge_for_the_chosen_provider_in_the_data_directory(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);

        $commandTester->execute([]);

        self::assertSame([['openai', $this->dataHome.'/symfony-security-auditor']], $this->recordingBridgeInstaller->installations);
    }

    public function test_it_derives_the_api_key_variable_from_the_provider_name_by_default(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['gemini', 'gemini-2.5-pro', '', '']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'gemini', 'platform' => ['gemini' => ['api_key' => '%env(GEMINI_API_KEY)%']], 'model' => 'gemini-2.5-pro'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_strips_invalid_characters_when_deriving_the_api_key_variable_from_the_provider(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['my-ai', 'my-model', '', '']);

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
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'no']);

        $commandTester->execute([]);

        self::assertSame(['model' => 'keep-me'], Yaml::parseFile($this->configFile()));
    }

    public function test_it_does_not_install_a_bridge_when_the_overwrite_is_declined(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'no']);

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
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);

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
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'no']);

        $commandTester->execute([]);

        self::assertStringContainsString('--force', $commandTester->getDisplay());
    }

    /**
     * @param array<string, string> $options
     */
    #[DataProvider('refusedOverAnExistingConfigurationCases')]
    public function test_it_refuses_what_it_cannot_write_before_asking_to_overwrite_the_existing_configuration(array $options): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();

        $commandTester->execute($options);

        self::assertStringNotContainsString('Overwrite it?', $commandTester->getDisplay());
    }

    /**
     * @param array<string, string> $options
     */
    #[DataProvider('refusedOverAnExistingConfigurationCases')]
    public function test_it_reports_the_refusal_rather_than_an_aborted_overwrite(array $options): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();

        self::assertSame(Command::INVALID, $commandTester->execute($options));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function refusedOverAnExistingConfigurationCases(): iterable
    {
        yield 'a platform whose block it cannot write' => [['--provider' => 'lmstudio', '--model' => 'our-model']];
        yield 'a bedrock model naming no vendor' => [['--provider' => 'bedrock.prod', '--model' => 'claude-opus-4-8']];
        yield 'a platform left without its required base url' => [['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN']];
    }

    public function test_it_overwrites_an_existing_configuration_when_confirmed(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'yes', '']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_its_success_message_points_at_the_docs_instead_of_a_paste_ready_export_line(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);
        $commandTester->execute([]);

        $display = preg_replace('/\s+/', ' ', $commandTester->getDisplay());

        self::assertStringContainsString('docs/configuration.md#providing-the-api-key', (string) $display);
        self::assertStringNotContainsString('export', (string) $display);
    }

    public function test_it_reports_success(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));
    }

    /**
     * @param array<string, string> $options
     */
    #[DataProvider('blankOrInvalidInputs')]
    public function test_it_rejects_a_blank_or_invalid_input_without_writing_configuration(array $options): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute($options, ['interactive' => false]);

        self::assertSame(Command::INVALID, $exitCode);
        self::assertFileDoesNotExist($this->configFile());
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function blankOrInvalidInputs(): iterable
    {
        yield 'empty provider' => [['--provider' => '', '--model' => 'gpt-5.4']];
        yield 'whitespace provider' => [['--provider' => '   ', '--model' => 'gpt-5.4']];
        yield 'blank model' => [['--provider' => 'openai', '--model' => '   ']];
        yield 'env var with a space' => [['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => 'MY KEY']];
        yield 'env var starting with a digit' => [['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => '1KEY']];
        yield 'env var with a parenthesis' => [['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => 'KEY)']];
        yield 'empty env var' => [['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => '']];
        yield 'provider with invalid utf-8 bytes' => [['--provider' => "caf\xE9", '--model' => 'gpt-5.4']];
        yield 'model with invalid utf-8 bytes' => [['--provider' => 'openai', '--model' => "caf\xE9"]];
        yield 'model read as a container parameter' => [['--provider' => 'openai', '--model' => 'gpt-%v%']];
        yield 'env var with invalid utf-8 bytes' => [['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => "\xE9KEY"]];
    }

    public function test_it_does_not_install_a_bridge_for_a_blank_provider(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => '', '--model' => 'gpt-5.4'], ['interactive' => false]);

        self::assertSame([], $this->recordingBridgeInstaller->installations);
    }

    /**
     * @param array<string, string> $options
     */
    #[DataProvider('violationMessages')]
    public function test_it_explains_why_an_input_was_rejected(array $options, string $expectedMessage): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute($options, ['interactive' => false]);

        self::assertStringContainsString($expectedMessage, $commandTester->getDisplay());
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function violationMessages(): iterable
    {
        yield 'empty provider' => [['--provider' => '', '--model' => 'gpt-5.4'], 'The provider must not be empty.'];
        yield 'invalid utf-8 provider' => [['--provider' => "caf\xE9", '--model' => 'gpt-5.4'], 'The provider must be valid UTF-8 text.'];
        yield 'blank model' => [['--provider' => 'openai', '--model' => ' '], 'The model must not be empty.'];
        yield 'invalid utf-8 model' => [['--provider' => 'openai', '--model' => "caf\xE9"], 'The model must be valid UTF-8 text.'];
        yield 'model read as a container parameter' => [['--provider' => 'openai', '--model' => 'gpt-%v%'], 'would be read as a container parameter'];
        yield 'invalid env var name' => [['--provider' => 'openai', '--model' => 'gpt-5.4', '--env-var' => 'MY KEY'], 'not a valid environment variable name'];
    }

    public function test_it_trims_surrounding_whitespace_from_the_model_and_env_var_options(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'openai', '--model' => ' gpt-5.4 ', '--env-var' => ' MY_KEY '],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(MY_KEY)%']], 'model' => 'gpt-5.4'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_leaves_the_configuration_unwritten_when_the_bridge_install_fails(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null, $this->dataHome);
        $initCommand = new InitCommand(
            $xdgConfigPathResolver,
            new StandaloneConfigFactory(),
            new YamlStandaloneConfigWriter(),
            new FailingBridgeInstaller(),
            new FilesystemCredentialStore($xdgConfigPathResolver),
        );
        $commandTester = new CommandTester($initCommand);

        try {
            $this->expectException(BridgeInstallationFailedException::class);

            $commandTester->execute(['--provider' => 'openai', '--model' => 'gpt-5.4'], ['interactive' => false]);
        } finally {
            self::assertFileDoesNotExist($this->configFile());
        }
    }

    public function test_it_confirms_where_the_configuration_was_written(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);

        $commandTester->execute([]);

        self::assertStringContainsString('Configuration written to', $commandTester->getDisplay());
    }

    public function test_it_names_the_api_key_variable_the_user_chose(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'MY_CUSTOM_KEY', '']);

        $commandTester->execute([]);

        $display = preg_replace('/\s+/', ' ', $commandTester->getDisplay());

        self::assertStringContainsString('Export MY_CUSTOM_KEY before auditing', (string) $display);
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_stores_the_api_key_the_user_pastes(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'openai-test-key-pasted-at-init']);

        $commandTester->execute([]);

        self::assertSame('openai-test-key-pasted-at-init', $this->storedCredential('OPENAI_API_KEY'));
    }

    public function test_it_names_the_stored_key_without_printing_it(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'openai-test-key-pasted-at-init']);

        $commandTester->execute([]);

        $display = $this->unwrappedDisplay($commandTester);

        self::assertStringContainsString('Stored OPENAI_API_KEY (openai…init)', $display);
        self::assertStringNotContainsString('openai-test-key-pasted-at-init', $display);
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_stores_nothing_when_the_user_skips_the_key(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);

        $commandTester->execute([]);

        self::assertNull($this->storedCredential('OPENAI_API_KEY'));
    }

    public function test_it_does_not_try_to_store_a_key_the_user_skipped(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);
        $commandTester->execute([]);

        $display = $this->unwrappedDisplay($commandTester);

        self::assertStringNotContainsString('could not be stored', $display);
    }

    public function test_it_still_reports_success_when_the_key_cannot_be_stored(): void
    {
        (new Filesystem())->mkdir($this->configHome.'/symfony-security-auditor/credentials.json');

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'openai-test-key-pasted-at-init']);

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));
    }

    public function test_it_tells_the_user_to_export_the_variable_when_the_key_cannot_be_stored(): void
    {
        (new Filesystem())->mkdir($this->configHome.'/symfony-security-auditor/credentials.json');

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'openai-test-key-pasted-at-init']);
        $commandTester->execute([]);

        $display = $this->unwrappedDisplay($commandTester);

        self::assertStringContainsString('Export OPENAI_API_KEY before auditing instead.', $display);
    }

    public function test_it_does_not_claim_to_have_stored_a_key_it_could_not_store(): void
    {
        (new Filesystem())->mkdir($this->configHome.'/symfony-security-auditor/credentials.json');

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'openai-test-key-pasted-at-init']);
        $commandTester->execute([]);

        $display = $this->unwrappedDisplay($commandTester);

        self::assertStringNotContainsString('You can run "audit', $display);
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    private function storedCredential(string $variableName): ?string
    {
        return (new FilesystemCredentialStore(new XdgConfigPathResolver($this->configHome, null, null, $this->dataHome)))->read($variableName);
    }

    public function test_it_treats_an_empty_answer_as_declining_the_overwrite(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', '']);

        $commandTester->execute([]);

        self::assertSame(['model' => 'keep-me'], Yaml::parseFile($this->configFile()));
    }

    public function test_it_warns_when_it_leaves_the_existing_configuration_untouched(): void
    {
        (new Filesystem())->dumpFile($this->configFile(), "model: keep-me\n");

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'no']);

        $commandTester->execute([]);

        self::assertStringContainsString('Aborted', $commandTester->getDisplay());
    }

    /**
     * @param array<string, string> $options
     */
    #[DataProvider('instanceKeyedOptionCases')]
    public function test_it_writes_an_instance_keyed_platform_nested_under_its_instance(array $options, string $expectedApiKey): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute($options, ['interactive' => false]);

        self::assertSame(
            [
                'provider' => 'generic.my_gateway',
                'platform' => ['generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => $expectedApiKey]]],
                'model' => 'our-model',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function instanceKeyedOptionCases(): iterable
    {
        yield 'an explicit env var is used verbatim' => [
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            '%env(GATEWAY_TOKEN)%',
        ];

        yield 'an omitted env var is derived from the platform, not the instance' => [
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--base-url' => 'https://gw.example'],
            '%env(GENERIC_API_KEY)%',
        ];
    }

    public function test_it_does_not_ask_for_a_base_url_when_the_platform_has_no_such_key(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        $commandTester->execute([]);

        self::assertStringNotContainsString('Base URL of the endpoint', $commandTester->getDisplay());
    }

    public function test_it_asks_for_a_base_url_when_a_flat_platform_requires_one(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['albert', 'our-model', 'ALBERT_API_KEY', 'https://albert.example']);

        $commandTester->execute([]);

        self::assertStringContainsString('Base URL of the endpoint', $commandTester->getDisplay());
    }

    public function test_it_writes_the_base_url_of_a_flat_platform_beside_its_api_key(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'albert', '--model' => 'our-model', '--env-var' => 'ALBERT_API_KEY', '--base-url' => 'https://albert.example'],
            ['interactive' => false],
        );

        self::assertSame(
            [
                'provider' => 'albert',
                'platform' => ['albert' => ['base_url' => 'https://albert.example', 'api_key' => '%env(ALBERT_API_KEY)%']],
                'model' => 'our-model',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_rejects_a_base_url_for_a_platform_that_exposes_none(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'anthropic', '--model' => 'claude-opus-5', '--base-url' => 'https://nope.example'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_names_the_platforms_that_take_a_base_url_when_rejecting_one(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'anthropic', '--model' => 'claude-opus-5', '--base-url' => 'https://nope.example'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'albert, amazeeai, generic.<instance>, openresponses.<instance>',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_refuses_a_platform_whose_block_it_cannot_write(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'lmstudio', '--model' => 'our-model', '--env-var' => 'LMSTUDIO_API_KEY'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_writes_bedrock_on_the_mantle_route_serving_the_model(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'bedrock.prod', '--model' => 'anthropic.claude-opus-4-8'], ['interactive' => false]);

        self::assertSame(
            [
                'provider' => 'bedrock.prod',
                'platform' => ['bedrock' => ['prod' => ['api' => 'messages', 'api_key' => '%env(BEDROCK_API_KEY)%']]],
                'model' => 'anthropic.claude-opus-4-8',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    /**
     * @param list<string> $expectedPlatforms
     */
    #[DataProvider('bridgeInstallCases')]
    public function test_it_installs_the_bridge_each_route_borrows_its_protocol_from(string $provider, string $model, array $expectedPlatforms): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => $provider, '--model' => $model], ['interactive' => false]);

        self::assertSame(
            [[$expectedPlatforms[0], $this->dataHome.'/symfony-security-auditor', ...\array_slice($expectedPlatforms, 1)]],
            $this->recordingBridgeInstaller->installations,
        );
    }

    public function test_it_installs_every_bridge_a_route_needs_in_a_single_composer_run(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'bedrock.prod', '--model' => 'openai.gpt-oss-120b'], ['interactive' => false]);

        self::assertCount(1, $this->recordingBridgeInstaller->installations);
    }

    public function test_it_names_every_bridge_it_downloads(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'bedrock.prod', '--model' => 'openai.gpt-oss-120b'], ['interactive' => false]);

        self::assertStringContainsString('Downloading the bedrock and generic provider bridges with composer', $this->unwrappedDisplay($commandTester));
    }

    /**
     * @return iterable<string, array{string, string, list<string>}>
     */
    public static function bridgeInstallCases(): iterable
    {
        yield 'bedrock on chat completions borrows the generic bridge' => ['bedrock.prod', 'openai.gpt-oss-120b', ['bedrock.prod', 'generic']];
        yield 'bedrock on messages needs nothing more' => ['bedrock.prod', 'anthropic.claude-opus-4-8', ['bedrock.prod']];
        yield 'any other platform installs its own bridge alone' => ['openai', 'openai.gpt-oss-120b', ['openai']];
    }

    public function test_it_writes_nothing_for_a_bedrock_model_that_names_no_vendor(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(['--provider' => 'bedrock.prod', '--model' => 'claude-opus-4-8'], ['interactive' => false]);

        self::assertSame(Command::INVALID, $exitCode);
        self::assertFileDoesNotExist($this->configFile());
    }

    public function test_it_says_what_a_hand_written_platform_needs_instead(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'azure.prod', '--model' => 'our-model', '--env-var' => 'AZURE_API_KEY'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'needs a "deployment" name beside the api_key, which "init" does not ask for',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_writes_nothing_for_a_platform_it_cannot_configure(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'transformersphp', '--model' => 'our-model', '--env-var' => 'TRANSFORMERS_API_KEY'],
            ['interactive' => false],
        );

        self::assertFileDoesNotExist($this->configFile());
    }

    public function test_it_still_installs_the_bridge_of_a_platform_whose_block_it_cannot_write(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'lmstudio', '--model' => 'our-model'], ['interactive' => false]);

        self::assertSame([['lmstudio', $this->dataHome.'/symfony-security-auditor']], $this->recordingBridgeInstaller->installations);
    }

    public function test_it_prints_the_block_to_complete_for_a_platform_whose_block_it_cannot_write(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'azure.prod', '--model' => 'our-model'], ['interactive' => false]);

        self::assertStringContainsString("deployment: '<deployment>'", $commandTester->getDisplay());
    }

    public function test_it_prints_the_block_with_the_model_it_was_given_trimmed(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'azure.prod', '--model' => ' our-model '], ['interactive' => false]);

        self::assertStringContainsString("model: our-model\n", $commandTester->getDisplay());
    }

    public function test_it_prints_the_block_as_yaml_ready_to_paste(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'azure'], ['interactive' => false]);

        self::assertStringContainsString(
            <<<'YAML'
                provider: azure.default
                platform:
                    azure:
                        default:
                            base_url: 'https://<resource>.openai.azure.com'
                            deployment: '<deployment>'
                            api_version: '<api version>'
                            api_key: '%env(AZURE_API_KEY)%'
                model: '<model id>'
                YAML,
            $commandTester->getDisplay(),
        );
    }

    public function test_the_block_it_prints_reads_back_the_model_it_was_given_as_a_string(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'lmstudio', '--model' => '.inf'], ['interactive' => false]);

        preg_match('/^"?provider"?: .*/ms', $commandTester->getDisplay(), $block);
        self::assertSame(
            ['provider' => 'lmstudio', 'platform' => ['lmstudio' => ['host_url' => 'http://127.0.0.1:1234']], 'model' => '.inf'],
            Yaml::parse($block[0] ?? ''),
        );
    }

    public function test_the_configuration_it_writes_reads_back_the_model_it_was_given_as_a_string(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'openai', '--model' => '.nan'], ['interactive' => false]);

        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => '.nan'],
            Yaml::parseFile($this->configFile()),
        );
    }

    #[DataProvider('platformsTheStandaloneBinaryCannotBootCases')]
    public function test_it_refuses_a_platform_the_standalone_binary_cannot_boot(string $provider): void
    {
        $commandTester = $this->commandTester();

        self::assertSame(Command::INVALID, $commandTester->execute(['--provider' => $provider, '--model' => 'our-model'], ['interactive' => false]));
    }

    #[DataProvider('platformsTheStandaloneBinaryCannotBootCases')]
    public function test_it_installs_no_bridge_for_a_platform_the_standalone_binary_cannot_boot(string $provider): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => $provider, '--model' => 'our-model'], ['interactive' => false]);

        self::assertSame([], $this->recordingBridgeInstaller->installations);
    }

    #[DataProvider('platformsTheStandaloneBinaryCannotBootCases')]
    public function test_it_offers_no_block_to_paste_for_a_platform_the_standalone_binary_cannot_boot(string $provider): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => $provider, '--model' => 'our-model'], ['interactive' => false]);

        self::assertStringNotContainsString('platform:', $commandTester->getDisplay());
    }

    public function test_it_says_why_the_standalone_binary_cannot_boot_a_platform_wrapping_others(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'failover.prod', '--model' => 'our-model'], ['interactive' => false]);

        self::assertStringContainsString(
            '"failover.prod" wraps other platforms through a rate limiter service, which only a Symfony application defines',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_says_a_platform_wrapping_others_cannot_boot_before_asking_for_an_instance(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'cache', '--model' => 'our-model'], ['interactive' => false]);

        self::assertStringContainsString(
            '"cache" wraps other platforms through the serializer service, which only a Symfony application defines',
            $this->unwrappedDisplay($commandTester),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function platformsTheStandaloneBinaryCannotBootCases(): iterable
    {
        yield 'failover, named without an instance' => ['failover'];
        yield 'failover, named with one' => ['failover.prod'];
        yield 'cache' => ['cache.prod'];
    }

    public function test_it_names_the_instance_the_block_is_written_for(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'azure', '--model' => 'our-model'], ['interactive' => false]);

        self::assertStringContainsString('provider: azure.default', $commandTester->getDisplay());
    }

    public function test_it_puts_the_model_it_was_given_into_the_block(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'lmstudio', '--model' => 'qwen3-coder'], ['interactive' => false]);

        self::assertStringContainsString('model: qwen3-coder', $commandTester->getDisplay());
    }

    public function test_it_leaves_a_placeholder_for_the_model_it_was_not_given(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'lmstudio'], ['interactive' => false]);

        self::assertStringContainsString("model: '<model id>'", $commandTester->getDisplay());
    }

    public function test_it_refuses_an_instance_keyed_platform_named_without_an_instance(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_shows_the_instance_syntax_when_the_instance_is_missing(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'openresponses', '--model' => 'our-model', '--env-var' => 'TOKEN'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'use "openresponses.<instance>", for example "openresponses.my_gateway"',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_writes_nothing_for_an_instance_keyed_platform_named_without_an_instance(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertFileDoesNotExist($this->configFile());
    }

    public function test_it_says_a_platform_is_unwritable_before_asking_for_an_instance(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'azure', '--model' => 'our-model', '--env-var' => 'AZURE_API_KEY'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'needs a "deployment" name beside the api_key',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_writes_a_numbered_instance_other_than_zero(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.42', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(
            [
                'provider' => 'generic.42',
                'platform' => ['generic' => [42 => ['base_url' => 'https://gw.example', 'api_key' => '%env(GATEWAY_TOKEN)%']]],
                'model' => 'our-model',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_names_the_missing_platform_even_when_a_base_url_is_given(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => '.gateway', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'names no platform before the dot',
            $this->unwrappedDisplay($commandTester),
        );
    }

    /**
     * @return iterable<string, array{array<string, string>, string, string}>
     */
    public static function textThatIsNotPlain(): iterable
    {
        yield 'a provider carrying a terminal escape sequence' => [['--provider' => "generic.\e]0;pwned\x07gateway", '--model' => 'our-model', '--env-var' => 'TOKEN'], 'The provider must not hold a control character, a line break or a bidirectional override.', "\e]0;pwned"];
        yield 'a provider carrying an eight-bit control' => [['--provider' => "generic.\u{9B}2Jgateway", '--model' => 'our-model', '--env-var' => 'TOKEN'], 'The provider must not hold a control character, a line break or a bidirectional override.', "\u{9B}"];
        yield 'a hand-written platform carrying a terminal escape sequence' => [['--provider' => "azure.x\e]0;pwned\x07y", '--model' => 'our-model', '--env-var' => 'TOKEN'], 'The provider must not hold a control character, a line break or a bidirectional override.', "\e]0;pwned"];
        yield 'a model carrying a workflow command line' => [['--provider' => 'bedrock.x', '--model' => "gpt\n::stop-commands::pwned", '--env-var' => 'TOKEN'], 'The model must not hold a control character, a line break or a bidirectional override.', "\n::stop-commands::"];
        yield 'a model reversing its direction' => [['--provider' => 'openai', '--model' => "gpt\u{202E}denwp", '--env-var' => 'TOKEN'], 'The model must not hold a control character, a line break or a bidirectional override.', "\u{202E}"];
        yield 'a model for a hand-written platform carrying an eight-bit control' => [['--provider' => 'azure.prod', '--model' => "gpt\u{9B}2J\u{202E}rev", '--env-var' => 'TOKEN'], 'The model must not hold a control character, a line break or a bidirectional override.', "\u{9B}"];
        yield 'a model for a hand-written platform that is not UTF-8' => [['--provider' => 'azure.prod', '--model' => "caf\xE9", '--env-var' => 'TOKEN'], 'The model must be valid UTF-8 text.', "\xE9"];
    }

    /**
     * @param array<string, string> $input
     */
    #[DataProvider('textThatIsNotPlain')]
    public function test_it_refuses_a_provider_or_model_that_is_not_plain_text_before_quoting_it(array $input, string $refusal, string $rawText): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute($input, ['interactive' => false]);

        self::assertSame(Command::INVALID, $commandTester->getStatusCode());
        self::assertSame(1, substr_count($this->unwrappedDisplay($commandTester), $refusal));
        self::assertStringNotContainsString($rawText, $commandTester->getDisplay());
        self::assertStringNotContainsString('Downloading', $commandTester->getDisplay());
        self::assertFileDoesNotExist($this->configFile());
    }

    public function test_the_summary_quotes_an_accented_provider_and_model_as_written(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.équipe', '--model' => "modèle\tété", '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertStringContainsString('generic.équipe', $this->unwrappedDisplay($commandTester));
        self::assertStringContainsString("modèle\tété", $commandTester->getDisplay());
        self::assertSame(
            ['provider' => 'generic.équipe', 'platform' => ['generic' => ['équipe' => ['base_url' => 'https://gw.example', 'api_key' => '%env(TOKEN)%']]], 'model' => "modèle\tété"],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_refuses_an_instance_name_the_config_cannot_be_read_back_with(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic..inf', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
        self::assertStringContainsString(
            'cannot be read back with',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_names_the_stray_instance_before_the_base_url_rule(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'ollama.x', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'takes a single connection block',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_refuses_an_instance_the_container_would_read_as_a_parameter(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic.%gw%', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
        self::assertStringContainsString(
            'would be read as a container parameter',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_refuses_a_missing_base_url_when_the_prompt_reaches_end_of_input(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs([]);

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN'],
        );

        self::assertSame(Command::INVALID, $exitCode);
        self::assertStringContainsString('requires a base URL', $this->unwrappedDisplay($commandTester));
    }

    /**
     * @param array<string, string> $options
     */
    #[DataProvider('consoleMarkupCases')]
    public function test_it_reports_a_value_holding_console_markup_as_written(array $options, string $expected): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute($options, ['interactive' => false]);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringContainsString($expected, $this->unwrappedDisplay($commandTester));
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function consoleMarkupCases(): iterable
    {
        yield 'a model naming an unknown colour' => [['--provider' => 'openai', '--model' => 'a<fg=nope>model', '--env-var' => 'TOKEN'], 'a<fg=nope>model'];
        yield 'a provider naming an unknown colour' => [['--provider' => 'x<fg=nope>y', '--model' => 'our-model', '--env-var' => 'TOKEN'], 'x<fg=nope>y'];
        yield 'a provider holding a known tag is not swallowed' => [['--provider' => 'x<info>y', '--model' => 'our-model', '--env-var' => 'TOKEN'], 'x<info>y'];
    }

    public function test_it_says_the_bridge_is_downloading_before_the_wait(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'Downloading the generic provider bridge with composer',
            $this->unwrappedDisplay($commandTester),
        );
    }

    #[DataProvider('resolvedValueCases')]
    public function test_it_lists_the_values_it_resolved(string $label, string $value): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            \sprintf('%s %s', $label, $value),
            $this->unwrappedDisplay($commandTester),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function resolvedValueCases(): iterable
    {
        yield 'the provider it configured' => ['Provider', 'generic.my_gateway'];
        yield 'the model it wrote' => ['Model', 'our-model'];
        yield 'the variable the key is read from' => ['API key variable', 'GATEWAY_TOKEN'];
    }

    /**
     * @param array<string, string> $options
     */
    #[DataProvider('refusedProviderCases')]
    public function test_it_installs_no_bridge_for_a_provider_it_refuses(array $options): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute($options, ['interactive' => false]);

        self::assertSame([], $this->recordingBridgeInstaller->installations);
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function refusedProviderCases(): iterable
    {
        yield 'an instance-keyed platform with no instance' => [['--provider' => 'generic', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example']];
        yield 'an instance name yaml cannot key by' => [['--provider' => 'generic.0', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example']];
        yield 'an environment variable name that is not one' => [['--provider' => 'generic.gw', '--model' => 'our-model', '--env-var' => '9TOKEN', '--base-url' => 'https://gw.example']];
        yield 'a base url read as a container parameter' => [['--provider' => 'generic.gw', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example/%v%']];
        yield 'a required base url left empty' => [['--provider' => 'albert', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => '']];
    }

    public function test_it_refuses_the_provider_before_asking_anything_else(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['generic']);

        $commandTester->execute([]);

        self::assertStringNotContainsString('Which model should the auditor use?', $this->unwrappedDisplay($commandTester));
    }

    public function test_it_refuses_a_base_url_the_container_would_read_as_a_parameter(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example/%v%'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
        self::assertStringContainsString(
            'would be read as a container parameter',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_writes_a_percent_encoded_base_url_escaped_for_the_container(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example/v1%2Fx%3Fy'],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'generic.my_gateway', 'platform' => ['generic' => ['my_gateway' => ['base_url' => 'https://gw.example/v1%%2Fx%%3Fy', 'api_key' => '%env(TOKEN)%']]], 'model' => 'our-model'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_still_refuses_an_env_placeholder_inside_a_base_url(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://%env(GATEWAY_HOST)%/v1'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_accepts_a_base_url_that_is_an_env_placeholder(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => '%env(GATEWAY_URL)%'],
            ['interactive' => false],
        );

        self::assertSame(
            [
                'provider' => 'generic.my_gateway',
                'platform' => ['generic' => ['my_gateway' => ['base_url' => '%env(GATEWAY_URL)%', 'api_key' => '%env(TOKEN)%']]],
                'model' => 'our-model',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_refuses_an_instance_the_container_cannot_name_a_service_by(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => "generic.o'brien", '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
        self::assertStringContainsString(
            'a service name cannot contain',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_refuses_zero_as_an_instance_name(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic.0', '--model' => 'our-model', '--env-var' => 'TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_refuses_a_provider_naming_no_platform_before_the_dot(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => '.anthropic', '--model' => 'claude-opus-5', '--env-var' => 'TOKEN'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'names no platform before the dot',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_writes_a_hyphenated_instance_under_the_key_symfony_will_use(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.my-gateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(
            [
                'provider' => 'generic.my_gateway',
                'platform' => ['generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(GATEWAY_TOKEN)%']]],
                'model' => 'our-model',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_refuses_a_flat_platform_given_an_instance(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'anthropic.prod', '--model' => 'claude-opus-5', '--env-var' => 'ANTHROPIC_API_KEY'],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_says_to_drop_the_instance_from_a_flat_platform(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'anthropic.prod', '--model' => 'claude-opus-5', '--env-var' => 'ANTHROPIC_API_KEY'],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'drop the instance and use "anthropic"',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_keeps_the_instance_name_as_the_user_typed_it(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.myGateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(
            [
                'provider' => 'generic.myGateway',
                'platform' => ['generic' => ['myGateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(GATEWAY_TOKEN)%']]],
                'model' => 'our-model',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_installs_the_platform_bridge_rather_than_one_named_after_the_instance(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => 'https://gw.example'],
            ['interactive' => false],
        );

        self::assertSame(
            'symfony/ai-generic-platform',
            ComposerBridgeInstaller::packageFor($this->recordingBridgeInstaller->installations[0][0]),
        );
    }

    public function test_it_asks_for_a_base_url_when_the_provider_selects_a_platform_instance(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['generic.my_gateway', 'our-model', 'GATEWAY_TOKEN', 'https://gw.example']);

        $commandTester->execute([]);

        self::assertSame(
            [
                'provider' => 'generic.my_gateway',
                'platform' => ['generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(GATEWAY_TOKEN)%']]],
                'model' => 'our-model',
            ],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_writes_nothing_when_a_required_base_url_is_answered_empty(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['generic.my_gateway', 'our-model', 'GATEWAY_TOKEN', '']);

        $commandTester->execute([]);

        self::assertFileDoesNotExist($this->configFile());
    }

    public function test_it_refuses_an_empty_base_url_rather_than_writing_a_config_that_cannot_boot(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--env-var' => 'GATEWAY_TOKEN', '--base-url' => ''],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_says_a_base_url_is_required_when_none_is_given(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'albert', '--model' => 'our-model', '--env-var' => 'ALBERT_API_KEY', '--base-url' => '  '],
            ['interactive' => false],
        );

        self::assertStringContainsString(
            'requires a base URL, so nothing was written',
            $this->unwrappedDisplay($commandTester),
        );
    }

    public function test_it_writes_a_local_platform_with_its_endpoint_and_no_credential(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['ollama', 'llama3.2', '', 'http://localhost:11434']);

        $commandTester->execute([]);

        self::assertSame(
            ['provider' => 'ollama', 'platform' => ['ollama' => ['endpoint' => 'http://localhost:11434']], 'model' => 'llama3.2'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_never_asks_for_a_key_to_store_when_it_wrote_no_credential(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['ollama', 'llama3.2', '', 'http://localhost:11434']);

        $commandTester->execute([]);

        self::assertStringNotContainsString('Paste the API key', $this->unwrappedDisplay($commandTester));
    }

    public function test_it_writes_the_endpoint_and_the_credential_when_both_are_given(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'ollama', '--model' => 'llama3.2', '--endpoint' => 'https://ollama.com', '--env-var' => 'OLLAMA_API_KEY'],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'ollama', 'platform' => ['ollama' => ['endpoint' => 'https://ollama.com', 'api_key' => '%env(OLLAMA_API_KEY)%']], 'model' => 'llama3.2'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_refuses_a_platform_that_declares_no_default_endpoint_when_none_is_given(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(['--provider' => 'ollama', '--model' => 'llama3.2'], ['interactive' => false]);

        self::assertSame(Command::INVALID, $exitCode);
    }

    public function test_it_writes_nothing_when_it_refuses_the_missing_endpoint(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(['--provider' => 'ollama', '--model' => 'llama3.2'], ['interactive' => false]);

        self::assertFileDoesNotExist($this->configFile());
    }

    public function test_it_drops_the_credential_when_asked_to_write_none(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'generic.my_gateway', '--model' => 'our-model', '--base-url' => 'https://gw.example', '--no-api-key' => true],
            ['interactive' => false],
        );

        self::assertSame(
            ['provider' => 'generic.my_gateway', 'platform' => ['generic' => ['my_gateway' => ['base_url' => 'https://gw.example']]], 'model' => 'our-model'],
            Yaml::parseFile($this->configFile()),
        );
    }

    public function test_it_says_the_configuration_carries_no_credential(): void
    {
        $commandTester = $this->commandTester();

        $commandTester->execute(
            ['--provider' => 'ollama', '--model' => 'llama3.2', '--endpoint' => 'http://localhost:11434'],
            ['interactive' => false],
        );

        self::assertStringContainsString('none — this platform is configured without a credential', $this->unwrappedDisplay($commandTester));
    }

    #[DataProvider('inapplicableOptionCases')]
    public function test_it_refuses_an_option_the_platform_does_not_take(string $option, string $value): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(
            ['--provider' => 'anthropic', '--model' => 'claude-opus-5', $option => $value],
            ['interactive' => false],
        );

        self::assertSame(Command::INVALID, $exitCode);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function inapplicableOptionCases(): iterable
    {
        yield 'an endpoint for a platform declaring none' => ['--endpoint', 'http://localhost:11434'];
        yield 'an omitted key for a platform requiring one' => ['--no-api-key', '1'];
    }

    public function test_it_offers_to_keep_the_default_endpoint_when_the_platform_carries_one(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['deepgram', 'nova-3', 'DEEPGRAM_API_KEY', '', '']);

        $commandTester->execute([]);

        self::assertStringContainsString('or leave it empty to keep the default', $this->unwrappedDisplay($commandTester));
    }

    public function test_it_offers_no_such_default_for_the_platform_that_declares_none(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['ollama', 'llama3.2', '', 'http://localhost:11434']);

        $commandTester->execute([]);

        self::assertStringNotContainsString('or leave it empty to keep the default', $this->unwrappedDisplay($commandTester));
    }

    private function commandTester(): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null, $this->dataHome);
        $initCommand = new InitCommand(
            $xdgConfigPathResolver,
            new StandaloneConfigFactory(),
            new YamlStandaloneConfigWriter(),
            $this->recordingBridgeInstaller,
            new FilesystemCredentialStore($xdgConfigPathResolver),
        );

        return new CommandTester($initCommand);
    }

    private function unwrappedDisplay(CommandTester $commandTester): string
    {
        return (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay());
    }

    private function configFile(): string
    {
        return $this->configHome.'/symfony-security-auditor/config.yaml';
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_replaces_a_credential_file_it_cannot_parse_when_storing_the_key(): void
    {
        (new Filesystem())->dumpFile($this->configHome.'/symfony-security-auditor/credentials.json', 'not json{');

        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY', 'openai-test-key-pasted-at-init']);
        $commandTester->execute([]);

        self::assertSame('openai-test-key-pasted-at-init', $this->storedCredential('OPENAI_API_KEY'));
    }

    public function test_it_explains_when_the_terminal_cannot_hide_the_key(): void
    {
        $commandTester = $this->commandTesterThatCannotHideInput();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));
        $display = $this->unwrappedDisplay($commandTester);

        self::assertStringContainsString('cannot hide what you type', $display);
        self::assertStringContainsString('export OPENAI_API_KEY before auditing', $display);
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_stores_nothing_when_the_terminal_cannot_hide_the_key(): void
    {
        $commandTester = $this->commandTesterThatCannotHideInput();
        $commandTester->setInputs(['openai', 'gpt-5.4', 'OPENAI_API_KEY']);

        $commandTester->execute([]);

        self::assertNull($this->storedCredential('OPENAI_API_KEY'));
    }

    private function commandTesterThatCannotHideInput(): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null, $this->dataHome);

        return new CommandTester(new InitCommand(
            $xdgConfigPathResolver,
            new StandaloneConfigFactory(),
            new YamlStandaloneConfigWriter(),
            $this->recordingBridgeInstaller,
            new FilesystemCredentialStore($xdgConfigPathResolver),
            credentialPrompt: new UnhideableCredentialPrompt(),
        ));
    }
}
