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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ExitCode;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\ProviderBridgeException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

final class ClaudeCodePlatformTest extends TestCase
{
    private const string ANSWER = '{"type":"result","subtype":"success","is_error":false,"result":"OK","usage":{"input_tokens":3,"output_tokens":1}}';

    private string $workingDirectory;

    #[Override]
    protected function setUp(): void
    {
        $this->workingDirectory = sys_get_temp_dir().'/ssa-claude-code-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->workingDirectory);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->workingDirectory);
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_runs_with_its_built_in_tools_off(): void
    {
        $this->invoke([]);

        self::assertContains(['--tools', ''], $this->consecutiveArgumentPairs());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_loads_no_settings_file_so_no_api_key_helper_replaces_the_subscription(): void
    {
        $this->invoke([]);

        self::assertContains(['--setting-sources', ''], $this->consecutiveArgumentPairs());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function variablesThatBillInPlaceOfTheSubscription(): iterable
    {
        yield 'an Anthropic API key' => ['ANTHROPIC_API_KEY'];
        yield 'an Anthropic auth token' => ['ANTHROPIC_AUTH_TOKEN'];
        yield 'AWS Bedrock' => ['CLAUDE_CODE_USE_BEDROCK'];
        yield 'Google Vertex AI' => ['CLAUDE_CODE_USE_VERTEX'];
        yield 'Microsoft Foundry' => ['CLAUDE_CODE_USE_FOUNDRY'];
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[DataProvider('variablesThatBillInPlaceOfTheSubscription')]
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_never_sees_a_variable_that_bills_in_place_of_the_subscription(string $variable): void
    {
        putenv(\sprintf('%s=1', $variable));
        $_SERVER[$variable] = '1';
        $this->invoke([]);

        self::assertStringNotContainsString(\sprintf('%s=', $variable), (string) file_get_contents($this->environmentFile()));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_ignores_the_mcp_servers_configured_on_the_machine(): void
    {
        $this->invoke([]);

        self::assertContains('--strict-mcp-config', $this->arguments());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_starts_in_a_directory_no_other_user_can_open(): void
    {
        $this->invoke([]);

        self::assertSame('drwx------', trim((string) file_get_contents($this->workingDirectory.'/cwd-mode')));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_starts_in_a_directory_whose_name_no_other_user_can_guess(): void
    {
        $this->invoke([]);

        self::assertMatchesRegularExpression('#/symfony-security-auditor-cli-[0-9a-f]{32}$#', trim((string) file_get_contents($this->workingDirectory.'/cwd')));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_starts_outside_the_audited_project_so_its_files_cannot_configure_it(): void
    {
        $this->invoke([]);

        self::assertStringStartsWith(realpath(sys_get_temp_dir()).'/', trim((string) file_get_contents($this->workingDirectory.'/cwd')));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_audit_asks_the_claude_code_cli_for_json_answers_since_the_cli_cannot_carry_the_auditor_tools(): void
    {
        $containerBuilder = $this->container();

        self::assertSame(
            [false, false, false, false],
            [
                $containerBuilder->getParameter('symfony_security_auditor.audit.tools_enabled'),
                $containerBuilder->getParameter('symfony_security_auditor.audit.structured_collection'),
                $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_tools_enabled'),
                $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_structured_collection'),
            ],
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_runs_at_the_configured_effort_and_stays_isolated(): void
    {
        $this->invoke([], ['effort' => 'high']);
        $pairs = $this->consecutiveArgumentPairs();

        self::assertSame([true, true, true], [\in_array(['--effort', 'high'], $pairs, true), \in_array(['--tools', ''], $pairs, true), \in_array('--strict-mcp-config', $this->arguments(), true)]);
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_keeps_its_own_effort_when_none_is_configured(): void
    {
        $this->invoke([]);

        self::assertNotContains('--effort', $this->arguments());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_a_budgeted_run_on_a_claude_subscription_is_refused_naming_the_budget(): void
    {
        $project = $this->workingDirectory.'/project';
        (new Filesystem())->dumpFile($project.'/src/Controller/HomeController.php', "<?php\n\nfinal class HomeController {}\n");
        $auditCommand = $this->container([], ['model' => 'claude-opus-5-5', 'audit' => ['budget' => ['max_cost_usd' => 5.0]]])->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);
        $commandTester = new CommandTester($auditCommand);

        $commandTester->execute(['project-path' => $project], ['interactive' => false]);

        self::assertStringContainsString('A subscription is not priced per call, so the cost budget cannot hold.', (string) preg_replace('/[\s!]+/', ' ', $commandTester->getDisplay()));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_a_dry_run_on_a_claude_subscription_says_it_is_not_priced_per_call(): void
    {
        $project = $this->workingDirectory.'/project';
        (new Filesystem())->dumpFile($project.'/src/Controller/HomeController.php', "<?php\n\nfinal class HomeController {}\n");
        $auditCommand = $this->container([], ['model' => 'claude-opus-5-5'])->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);
        $commandTester = new CommandTester($auditCommand);

        $commandTester->execute(['project-path' => $project, '--dry-run' => true], ['interactive' => false]);

        $display = (string) preg_replace('/[\s!\/]+/', ' ', $commandTester->getDisplay());

        self::assertSame([true, false], [str_contains($display, 'Your subscription is not billed per call, so no cost is shown.'), str_contains($display, 'typo')]);
    }

    /**
     * @param array<string, mixed>  $options
     * @param array<string, string> $settings
     *
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    private function invoke(array $options, array $settings = []): string
    {
        $platform = $this->container($settings)->get(PlatformInterface::class);
        self::assertInstanceOf(PlatformInterface::class, $platform);

        return $platform->invoke('opus', new MessageBag(Message::forSystem('Be terse.'), Message::ofUser('Audit this.')), $options)->asText();
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_report_of_a_run_on_a_claude_subscription_names_the_plan_it_billed(): void
    {
        $project = $this->workingDirectory.'/project';
        (new Filesystem())->dumpFile($project.'/src/Controller/HomeController.php', "<?php\n\nfinal class HomeController {}\n");
        $auditCommand = $this->container([], ['model' => 'claude-opus-5-5'])->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);
        $commandTester = new CommandTester($auditCommand);

        $commandTester->execute(['project-path' => $project], ['interactive' => false]);

        self::assertStringContainsString('Cost : billed to your Claude subscription (max plan)', (string) preg_replace('/[\s!]+/', ' ', $commandTester->getDisplay()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function costLabellingFormats(): iterable
    {
        yield 'console' => ['console'];
        yield 'markdown' => ['markdown'];
        yield 'html' => ['html'];
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[DataProvider('costLabellingFormats')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_report_of_a_run_whose_claude_cli_names_no_account_says_it_is_not_priced_per_call(string $format): void
    {
        $project = $this->workingDirectory.'/project';
        (new Filesystem())->dumpFile($project.'/src/Controller/HomeController.php', "<?php\n\nfinal class HomeController {}\n");
        $silentCli = $this->workingDirectory.'/silent-claude';
        (new Filesystem())->dumpFile($silentCli, str_replace('{"loggedIn":true,"subscriptionType":"max"}', 'no account status', (string) file_get_contents($this->fakeCli())));
        (new Filesystem())->chmod($silentCli, 0o755);
        $auditCommand = $this->container(['cli_binary' => $silentCli], ['model' => 'claude-opus-5-5'])->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);
        $commandTester = new CommandTester($auditCommand);

        $commandTester->execute(['project-path' => $project, '--format' => $format], ['interactive' => false]);

        self::assertStringContainsString('not priced per call: billed to your Claude subscription, or to an API key the CLI uses in its place', (string) preg_replace('/[\s!]+/', ' ', $commandTester->getDisplay()));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_audit_header_names_the_claude_subscription_the_run_bills(): void
    {
        $project = $this->workingDirectory.'/project';
        (new Filesystem())->dumpFile($project.'/src/Controller/HomeController.php', "<?php\n\nfinal class HomeController {}\n");
        $auditCommand = $this->container([], ['model' => 'claude-opus-5-5'])->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);
        $commandTester = new CommandTester($auditCommand);

        $commandTester->execute(['project-path' => $project], ['interactive' => false]);

        self::assertStringContainsString('Billing: your Claude subscription (max plan)', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_an_audit_on_a_claude_cli_that_is_not_logged_in_fails_before_it_starts(): void
    {
        $project = $this->workingDirectory.'/project';
        (new Filesystem())->dumpFile($project.'/src/Controller/HomeController.php', "<?php\n\nfinal class HomeController {}\n");
        $loggedOutCli = $this->workingDirectory.'/logged-out-claude';
        (new Filesystem())->dumpFile($loggedOutCli, "#!/bin/sh\necho '{\"loggedIn\":false}'\nexit 1\n");
        (new Filesystem())->chmod($loggedOutCli, 0o755);
        $auditCommand = $this->container(['cli_binary' => $loggedOutCli], ['model' => 'claude-opus-5-5'])->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);
        $commandTester = new CommandTester($auditCommand);

        $exitCode = $commandTester->execute(['project-path' => $project], ['interactive' => false]);

        self::assertSame([ExitCode::Failure->value, true], [$exitCode, str_contains((string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()), '[ERROR] Run "claude auth login" to log the Claude Code CLI in to your Claude subscription before an audit.')]);
    }

    /**
     * @param array<string, string> $settings
     * @param array<string, mixed>  $auditConfig
     *
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    private function container(array $settings = [], array $auditConfig = []): ContainerBuilder
    {
        return (new StandaloneContainerFactory())->create(
            new StandaloneConfig($auditConfig, new StandalonePlatformConfig(['claudecode' => ['cli_binary' => $this->fakeCli(), ...$settings]], 'claudecode')),
            $this->workingDirectory.'/cache',
        );
    }

    private function fakeCli(): string
    {
        $cli = $this->workingDirectory.'/claude';
        (new Filesystem())->dumpFile($cli, \sprintf("#!/bin/sh\nif [ \"\$1\" = auth ]; then echo '{\"loggedIn\":true,\"subscriptionType\":\"max\"}'; exit 0; fi\npwd -P > %s\nls -ld . | cut -c1-10 > %s\nprintf '%%s\\0' \"\$@\" > %s\nenv > %s\necho '%s'\n", escapeshellarg($this->workingDirectory.'/cwd'), escapeshellarg($this->workingDirectory.'/cwd-mode'), escapeshellarg($this->argumentsFile()), escapeshellarg($this->environmentFile()), self::ANSWER));
        (new Filesystem())->chmod($cli, 0o755);

        return $cli;
    }

    private function environmentFile(): string
    {
        return $this->workingDirectory.'/environment';
    }

    private function argumentsFile(): string
    {
        return $this->workingDirectory.'/arguments';
    }

    /**
     * @return list<string>
     */
    private function arguments(): array
    {
        return explode("\0", rtrim((string) file_get_contents($this->argumentsFile()), "\0"));
    }

    /**
     * @return list<list<string>>
     */
    private function consecutiveArgumentPairs(): array
    {
        $arguments = $this->arguments();

        return array_map(static fn (int $index): array => [$arguments[$index], $arguments[$index + 1]], array_keys(\array_slice($arguments, 0, -1)));
    }
}
