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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityFederation;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckResult;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Command\EnvironmentDoctorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ProviderSetupDoctor;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\FixedCliAgentAccountProbe;

final class ProviderSetupDoctorTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-provider-doctor-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    public function test_it_describes_the_provider_models_and_billing_after_the_other_checks(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: { effort: medium }\nmodel: claude-opus-5-5\nreviewer_model: claude-haiku-5-5\n");

        self::assertEquals(
            [
                new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.'),
                new DoctorCheckResult('Provider', DoctorCheckStatus::Ok, 'Claude (through the Claude Code CLI). Model: claude-opus-5-5, reviewed by claude-haiku-5-5, effort medium. Billing: your Claude subscription (max plan, dev@example.com).'),
            ],
            $this->doctor(CliAgentAccount::subscription('max plan, dev@example.com'))->diagnose(),
        );
    }

    public function test_it_warns_that_an_api_key_bills_in_place_of_the_subscription(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");

        self::assertEquals(
            new DoctorCheckResult('Provider', DoctorCheckStatus::Warning, 'Claude (through the Claude Code CLI). Model: opus. Billing: the API key in ANTHROPIC_API_KEY, not your Claude subscription. The Claude Code CLI bills the API key in ANTHROPIC_API_KEY, not your Claude subscription. Unset ANTHROPIC_API_KEY to run the audit on the subscription.'),
            $this->doctor(CliAgentAccount::apiKey('ANTHROPIC_API_KEY', 'Unset ANTHROPIC_API_KEY to run the audit on the subscription.'))->diagnose()[1],
        );
    }

    public function test_it_fails_while_the_cli_is_not_logged_in(): void
    {
        $this->writeConfig("provider: codex\nplatform:\n    codex: {}\nmodel: gpt-6-luna\n");

        self::assertSame(DoctorCheckStatus::Failure, $this->doctor(CliAgentAccount::notLoggedIn())->diagnose()[1]->status);
    }

    public function test_it_adds_nothing_while_no_provider_is_configured(): void
    {
        self::assertCount(1, $this->doctor(CliAgentAccount::subscription(null))->diagnose());
    }

    public function test_it_warns_when_the_cli_cannot_tell_which_account_it_bills(): void
    {
        $this->writeConfig("provider: claudecode\nplatform:\n    claudecode: {}\nmodel: opus\n");

        self::assertEquals(
            new DoctorCheckResult('Provider', DoctorCheckStatus::Warning, 'Claude (through the Claude Code CLI). Model: opus. Billing: unknown: "claude auth status" failed. Run "claude auth status" to see which account the Claude Code CLI bills.'),
            $this->doctor(CliAgentAccount::unknown('"claude auth status" failed'))->diagnose()[1],
        );
    }

    public function test_it_names_a_subscription_whose_cli_gives_no_account_detail(): void
    {
        $this->writeConfig("provider: codex\nplatform:\n    codex: {}\nmodel: gpt-6-luna\n");

        self::assertSame('ChatGPT (through the Codex CLI). Model: gpt-6-luna. Billing: your ChatGPT subscription.', $this->doctor(CliAgentAccount::subscription(null))->diagnose()[1]->detail);
    }

    public function test_it_points_to_codex_login_status_when_codex_cannot_tell_which_account_it_bills(): void
    {
        $this->writeConfig("provider: codex\nplatform:\n    codex: {}\nmodel: gpt-6-luna\n");

        self::assertStringEndsWith('Run "codex login status" to see which account the Codex CLI bills.', $this->doctor(CliAgentAccount::unknown('"codex login status" failed'))->diagnose()[1]->detail);
    }

    public function test_it_bills_each_call_through_the_workload_identity_federation_the_anthropic_provider_signs_in_with(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(ANTHROPIC_API_KEY)%'\nmodel: claude-opus-5-5\n");

        self::assertEquals(
            new DoctorCheckResult('Provider', DoctorCheckStatus::Ok, 'Anthropic (Claude). Model: claude-opus-5-5. Billing: per call, through workload identity federation (rule fdrl_rule).'),
            $this->doctor(CliAgentAccount::subscription(null), new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'))->diagnose()[1],
        );
    }

    private function doctor(CliAgentAccount $cliAgentAccount, ?WorkloadIdentityFederation $workloadIdentityFederation = null): ProviderSetupDoctor
    {
        $environmentDoctor = self::createStub(EnvironmentDoctorInterface::class);
        $environmentDoctor->method('diagnose')->willReturn([new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.')]);

        return new ProviderSetupDoctor(
            $environmentDoctor,
            new ConfiguredCredentialVariable(new XdgConfigPathResolver($this->configHome, null, null), workloadIdentityFederation: $workloadIdentityFederation),
            new FixedCliAgentAccountProbe($cliAgentAccount),
        );
    }

    private function writeConfig(string $contents): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $contents);
    }
}
