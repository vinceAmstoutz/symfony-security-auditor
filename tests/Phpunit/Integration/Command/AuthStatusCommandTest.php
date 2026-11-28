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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FilesystemCredentialStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ProcessCliAgentAccountProbe;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityFederation;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuthStatusCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\FixedCliAgentAccountProbe;

final class AuthStatusCommandTest extends TestCase
{
    private const string KEY = 'anthropic-test-key-for-previews';

    private Filesystem $filesystem;

    private string $configHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-auth-status-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    public function test_it_reports_a_key_coming_from_the_environment(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY]);

        $commandTester->execute([]);

        self::assertStringContainsString('Source the environment', $this->flattened($commandTester));
    }

    public function test_it_suggests_testing_a_key_that_resolves(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY]);

        $commandTester->execute([]);

        self::assertStringContainsString('Run "auth:test" to check that this key works. It sends one short test request, which a paid API bills, usually well under a cent.', $this->flattened($commandTester));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_a_key_coming_from_the_store(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', self::KEY);
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringContainsString('Source stored on this machine', $this->flattened($commandTester));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_names_the_key_without_printing_it(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', self::KEY);
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        $display = $this->flattened($commandTester);

        self::assertStringContainsString('Key anthro…iews Fingerprint SHA256:66ff24e605fe0e69', $display);
        self::assertStringNotContainsString(self::KEY, $display);
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_warns_that_an_exported_variable_shadows_the_stored_key(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', self::KEY);
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => 'anthropic-test-key-exported']);

        $commandTester->execute([]);

        self::assertStringContainsString('A key is also stored on this machine, but the exported ANTHROPIC_API_KEY wins', $this->flattened($commandTester));
    }

    public function test_it_stays_quiet_about_shadowing_when_nothing_is_stored(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY]);

        $commandTester->execute([]);

        self::assertStringNotContainsString('is also stored on this machine', $this->flattened($commandTester));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_stays_quiet_about_shadowing_when_the_stored_key_is_the_one_in_use(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', self::KEY);
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringNotContainsString('is also stored on this machine', $this->flattened($commandTester));
    }

    public function test_it_reports_a_variable_named_on_the_command_line(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester(['OPENAI_API_KEY' => self::KEY]);

        $commandTester->execute(['--env-var' => 'OPENAI_API_KEY']);

        self::assertStringContainsString('Variable OPENAI_API_KEY', $this->flattened($commandTester));
    }

    public function test_it_fails_when_no_key_resolves_at_all(): void
    {
        $this->writeConfig();

        self::assertSame(Command::FAILURE, $this->commandTester()->execute([]));
    }

    public function test_it_offers_every_way_of_supplying_a_missing_key(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        $display = $this->flattened($commandTester);

        self::assertStringContainsString('auth:set', $display);
        self::assertStringContainsString('export ANTHROPIC_API_KEY=', $display);
        self::assertStringContainsString('ANTHROPIC_API_KEY=$(pass show …) audit .', $display);
    }

    public function test_it_names_the_variable_that_resolved_to_nothing(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringContainsString('No API key resolves for ANTHROPIC_API_KEY', $this->flattened($commandTester));
    }

    public function test_it_introduces_the_options_it_offers(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringContainsString('Pick whichever fits how you work', $this->flattened($commandTester));
    }

    public function test_it_reports_the_workload_identity_federation_an_anthropic_audit_signs_in_with_in_place_of_an_api_key(): void
    {
        $this->writeConfig();
        $commandTester = $this->federatedCommandTester();

        self::assertSame(
            [Command::SUCCESS, true],
            [$commandTester->execute([]), str_contains($this->flattened($commandTester), '[OK] An audit uses no API key: it signs in through workload identity federation (rule fdrl_rule).')],
            $commandTester->getDisplay(),
        );
    }

    public function test_it_fails_when_an_anthropic_audit_cannot_sign_in_through_workload_identity_federation(): void
    {
        $this->writeConfig();
        $commandTester = $this->federatedCommandTester('The job cannot get an identity token.');

        $exitCode = $commandTester->execute([]);

        self::assertSame(
            [Command::FAILURE, true, false],
            [$exitCode, str_contains($this->flattened($commandTester), '[ERROR] The job cannot get an identity token.'), str_contains($this->flattened($commandTester), 'An audit uses no API key')],
            $commandTester->getDisplay(),
        );
    }

    public function test_a_variable_named_on_the_command_line_is_reported_under_workload_identity_federation_too(): void
    {
        $this->writeConfig();
        $commandTester = $this->federatedCommandTester();

        self::assertSame(
            [Command::FAILURE, true],
            [$commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']), str_contains($this->flattened($commandTester), 'No API key resolves for ANTHROPIC_API_KEY')],
            $commandTester->getDisplay(),
        );
    }

    public function test_a_variable_named_on_the_command_line_is_reported_whatever_refuses_the_federated_sign_in(): void
    {
        $this->writeConfig();
        $commandTester = $this->federatedCommandTester('The job cannot get an identity token.');

        $exitCode = $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']);

        self::assertSame(
            [Command::FAILURE, true, false],
            [$exitCode, str_contains($this->flattened($commandTester), 'No API key resolves for ANTHROPIC_API_KEY'), str_contains($this->flattened($commandTester), 'The job cannot get an identity token.')],
            $commandTester->getDisplay(),
        );
    }

    public function test_it_refuses_when_no_variable_is_configured_yet(): void
    {
        self::assertSame(Command::INVALID, $this->commandTester()->execute([]));
    }

    public function test_it_succeeds_when_the_configured_platform_needs_no_api_key(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");

        self::assertSame(Command::SUCCESS, $this->commandTester()->execute([]));
    }

    public function test_it_says_the_configured_platform_needs_no_api_key(): void
    {
        $this->writeConfig("provider: ollama\nplatform:\n    ollama: { endpoint: 'http://localhost:11434' }\nmodel: qwen3\n");
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('The configured platform needs no API key, so an audit uses none', $this->flattened($commandTester));
    }

    public function test_it_points_an_unconfigured_user_at_init(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Run "init" to create a configuration', $this->flattened($commandTester));
    }

    public function test_it_says_when_credentials_have_nowhere_to_live(): void
    {
        $commandTester = new CommandTester(new AuthStatusCommand(
            new FilesystemCredentialStore(new XdgConfigPathResolver(null, null, null)),
            new ConfiguredCredentialVariable(new XdgConfigPathResolver(null, null, null)),
            ['ANTHROPIC_API_KEY' => self::KEY],
        ));

        $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']);

        self::assertStringContainsString('no per-user configuration directory could be resolved', $this->flattened($commandTester));
    }

    /**
     * Collapses the block gutter SymfonyStyle draws down the left of a note,
     * so an assertion reads the sentence rather than where it happened to wrap.
     */
    public function test_it_names_the_provider_an_audit_runs_on(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Provider Claude (through the Claude Code CLI)', $this->flattened($commandTester));
    }

    public function test_it_names_the_models_and_the_effort_an_audit_runs_with(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: { effort: high }\nmodel: claude-opus-5-5\nreviewer_model: claude-haiku-5-5\n");
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Model claude-opus-5-5, reviewed by claude-haiku-5-5, effort high', $this->flattened($commandTester));
    }

    public function test_it_says_which_account_a_subscription_bills(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");
        $commandTester = $this->commandTester(cliAgentAccount: CliAgentAccount::subscription('Max plan, dev@example.com'));
        $commandTester->execute([]);

        self::assertStringContainsString('Billing your Claude subscription (Max plan, dev@example.com)', $this->flattened($commandTester));
    }

    public function test_it_warns_that_an_api_key_bills_in_place_of_the_subscription(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");
        $commandTester = $this->commandTester(cliAgentAccount: CliAgentAccount::apiKey('ANTHROPIC_API_KEY', 'Unset it to run the audit on the subscription.'));
        $commandTester->execute([]);

        self::assertStringContainsString('[WARNING] The Claude Code CLI bills the API key in ANTHROPIC_API_KEY, not your Claude subscription. Unset it to run the audit on the subscription.', $this->flattened($commandTester));
    }

    public function test_it_says_when_the_cli_is_not_logged_in(): void
    {
        $this->writeConfig("provider: codex\nplatform:\n    codex: {}\nmodel: gpt-6-luna\n");
        $commandTester = $this->commandTester(cliAgentAccount: CliAgentAccount::notLoggedIn());
        $commandTester->execute([]);

        self::assertStringContainsString('Billing nothing yet: the Codex CLI is not logged in', $this->flattened($commandTester));
    }

    public function test_it_says_how_to_log_the_cli_in(): void
    {
        $this->writeConfig("provider: codex\nplatform:\n    codex: {}\nmodel: gpt-6-luna\n");
        $commandTester = $this->commandTester(cliAgentAccount: CliAgentAccount::notLoggedIn());
        $commandTester->execute([]);

        self::assertStringContainsString('[WARNING] Run "codex login" to log the Codex CLI in to your ChatGPT subscription before an audit.', $this->flattened($commandTester));
    }

    public function test_it_says_why_the_billed_account_is_unknown(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");
        $commandTester = $this->commandTester(cliAgentAccount: CliAgentAccount::unknown('the claude CLI is not on the PATH'));
        $commandTester->execute([]);

        self::assertStringContainsString('Billing unknown: the claude CLI is not on the PATH', $this->flattened($commandTester));
    }

    public function test_it_says_an_api_key_bills_each_call(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY]);
        $commandTester->execute([]);

        self::assertStringContainsString('Billing per call, to the API key ANTHROPIC_API_KEY holds', $this->flattened($commandTester));
    }

    public function test_it_says_a_platform_without_a_key_bills_nothing_per_call(): void
    {
        $this->writeConfig("provider: ollama\nplatform:\n    ollama: { endpoint: 'http://localhost:11434' }\nmodel: qwen3\n");
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Billing nothing per call: Ollama takes no API key', $this->flattened($commandTester));
    }

    public function test_it_says_a_key_written_into_the_configuration_bills_each_call(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: 'anthropic-test-key-written-inline'\n");
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Billing per call, to the API key the configuration holds', $this->flattened($commandTester));
    }

    public function test_it_points_a_subscription_to_the_account_its_cli_bills(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");
        $commandTester = $this->commandTester(cliAgentAccount: CliAgentAccount::apiKey('ANTHROPIC_API_KEY', 'Unset it to run the audit on the subscription.'));
        $commandTester->execute([]);

        self::assertStringContainsString('[OK] The auditor stores no API key for this provider: its CLI bills the account under Billing.', $this->flattened($commandTester));
    }

    public function test_it_asks_the_cli_the_configuration_names_which_account_it_bills(): void
    {
        $cli = $this->configHome.'/bin/claude';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\necho '{\"loggedIn\":true,\"subscriptionType\":\"pro\"}'\n");
        $this->filesystem->chmod($cli, 0o755);
        $this->writeConfig(\sprintf("provider: claudecode\nplatform:\n    claudecode: { cli_binary: '%s' }\nmodel: opus\n", $cli));
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);
        $commandTester = new CommandTester(new AuthStatusCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
            cliAgentAccountProbe: new ProcessCliAgentAccountProbe(),
        ));
        $commandTester->execute([]);

        self::assertStringContainsString('Billing your Claude subscription (pro plan)', $this->flattened($commandTester));
    }

    public function test_it_names_a_gateway_by_what_it_is(): void
    {
        $this->writeConfig("platform:\n    generic:\n        base_url: 'https://gateway.example'\n        api_key: '%env(GATEWAY_API_KEY)%'\n");
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Provider Your OpenAI-compatible gateway', $this->flattened($commandTester));
    }

    private function flattened(CommandTester $commandTester): string
    {
        return (string) preg_replace('/[\s!]+/', ' ', $commandTester->getDisplay());
    }

    private function writeConfig(string $contents = "platform:\n    anthropic:\n        api_key: '%env(ANTHROPIC_API_KEY)%'\n"): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $contents);
    }

    /**
     * @param array<string, string> $environment
     */
    private function commandTester(array $environment = [], ?CliAgentAccount $cliAgentAccount = null): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);

        return new CommandTester(new AuthStatusCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
            $environment,
            cliAgentAccountProbe: new FixedCliAgentAccountProbe($cliAgentAccount ?? CliAgentAccount::subscription(null)),
        ));
    }

    private function federatedCommandTester(?string $federatedSignInRefusal = null): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);

        return new CommandTester(new AuthStatusCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver, workloadIdentityFederation: new WorkloadIdentityFederation('fdrl_rule', 'org-uuid')),
            cliAgentAccountProbe: new FixedCliAgentAccountProbe(CliAgentAccount::subscription(null)),
            federatedSignInRefusal: $federatedSignInRefusal,
        ));
    }

    private function store(): FilesystemCredentialStore
    {
        return new FilesystemCredentialStore(new XdgConfigPathResolver($this->configHome, null, null));
    }

    public function test_it_refuses_a_name_no_environment_variable_can_have(): void
    {
        $this->writeConfig();

        self::assertSame(Command::INVALID, $this->commandTester()->execute(['--env-var' => 'not-a-var']));
    }

    public function test_it_says_what_a_valid_variable_name_looks_like(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute(['--env-var' => 'not-a-var']);

        self::assertStringContainsString('"not-a-var" is not a valid environment variable name', $this->flattened($commandTester));
    }

    public function test_it_reports_the_key_a_credential_file_holds_rather_than_the_files_path(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%'\n");
        $credentialFile = $this->configHome.'/anthropic-api-key';
        $this->filesystem->dumpFile($credentialFile, self::KEY."\n");
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY_FILE' => $credentialFile]);

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));

        $display = $this->flattened($commandTester);

        self::assertStringContainsString('Source the file ANTHROPIC_API_KEY_FILE names', $display);
        self::assertStringContainsString('Key anthro…iews Fingerprint SHA256:66ff24e605fe0e69', $display);
    }

    public function test_it_fails_when_the_credential_file_cannot_be_read(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%'\n");
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY_FILE' => $this->configHome.'/absent-api-key']);

        self::assertSame(Command::FAILURE, $commandTester->execute([]));
        self::assertStringContainsString('The credential file your config reads through "ANTHROPIC_API_KEY_FILE" could not be read', $this->flattened($commandTester));
    }

    public function test_it_fails_when_the_credential_file_is_empty(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%'\n");
        $credentialFile = $this->configHome.'/blank-api-key';
        $this->filesystem->dumpFile($credentialFile, " \n");
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY_FILE' => $credentialFile]);

        self::assertSame(Command::FAILURE, $commandTester->execute([]));
        self::assertStringContainsString('The credential file your config reads through "ANTHROPIC_API_KEY_FILE" is empty', $this->flattened($commandTester));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_warns_that_an_exported_credential_file_shadows_the_stored_key(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%'\n");
        $this->store()->write('ANTHROPIC_API_KEY_FILE', self::KEY);
        $credentialFile = $this->configHome.'/anthropic-api-key';
        $this->filesystem->dumpFile($credentialFile, 'anthropic-test-key-from-file');
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY_FILE' => $credentialFile]);

        $commandTester->execute([]);

        self::assertStringContainsString('the exported ANTHROPIC_API_KEY_FILE wins', $this->flattened($commandTester));
    }

    public function test_a_variable_the_configuration_does_not_read_is_reported_as_its_own_value(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%'\n");
        $commandTester = $this->commandTester(['OPENAI_API_KEY' => self::KEY]);

        $commandTester->execute(['--env-var' => 'OPENAI_API_KEY']);

        self::assertStringContainsString('Source the environment Key anthro…iews', $this->flattened($commandTester));
    }

    public function test_the_variable_the_configuration_reads_through_a_file_is_reported_as_that_file_when_named_on_the_command_line(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%'\n");
        $credentialFile = $this->configHome.'/anthropic-api-key';
        $this->filesystem->dumpFile($credentialFile, self::KEY);
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY_FILE' => $credentialFile]);

        $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY_FILE']);

        self::assertStringContainsString('Source the file ANTHROPIC_API_KEY_FILE names Key anthro…iews', $this->flattened($commandTester));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_an_exported_key_is_reported_even_when_the_store_cannot_be_read(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', 'anthropic-test-key-in-an-open-store');
        $this->filesystem->chmod($this->configHome.'/symfony-security-auditor/credentials.json', 0644);
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY]);

        self::assertSame(Command::SUCCESS, $commandTester->execute([]));
        $display = $this->flattened($commandTester);
        self::assertStringContainsString('Source the environment Key anthro…iews', $display);
        self::assertStringContainsString('are readable by other users on this machine (permissions 0644)', $display);
        self::assertStringNotContainsString('is also stored on this machine', $display);
    }

    public function test_it_reports_on_the_provider_the_configuration_selects(): void
    {
        $this->writeConfig("provider: openai\nplatform:\n    anthropic:\n        api_key: '%env(ANTHROPIC_API_KEY)%'\n    openai:\n        api_key: '%env(OPENAI_API_KEY)%'\n");
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY, 'OPENAI_API_KEY' => 'openai-test-key-for-previews-2']);

        $commandTester->execute([]);

        self::assertStringContainsString('Variable OPENAI_API_KEY', $this->flattened($commandTester));
    }

    public function test_it_refuses_a_relative_home_override_instead_of_reporting_no_directory(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, null, null, 'relative/home');
        $commandTester = new CommandTester(new AuthStatusCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
        ));

        self::assertSame(Command::FAILURE, $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']));
        self::assertStringContainsString('SYMFONY_SECURITY_AUDITOR_HOME is set to "relative/home", which is not an absolute path', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
        self::assertSame(1, substr_count($commandTester->getDisplay(), '[ERROR]'), $commandTester->getDisplay());
        self::assertStringNotContainsString('ANTHROPIC_API_KEY', $commandTester->getDisplay());
    }
}
