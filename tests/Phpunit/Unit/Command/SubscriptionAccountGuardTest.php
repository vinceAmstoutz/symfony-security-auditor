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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ClaudeCodeSubscriptionCli;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\BilledSubscriptionHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\RunRefusedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\SubscriptionAccountGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuardInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class SubscriptionAccountGuardTest extends TestCase
{
    /**
     * @throws RunRefusedException
     */
    public function test_it_names_the_subscription_the_audit_bills_in_its_header(): void
    {
        $bufferedOutput = new BufferedOutput();

        $this->guard(CliAgentAccount::subscription('max plan, dev@example.com'))->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), $bufferedOutput));

        self::assertStringContainsString('Billing: your Claude subscription (max plan, dev@example.com)', (string) preg_replace('/\s+/', ' ', $bufferedOutput->fetch()));
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_hands_the_reports_the_plan_it_bills_without_the_account(): void
    {
        $billedSubscriptionHolder = new BilledSubscriptionHolder();

        $this->guard(CliAgentAccount::subscription('max plan, dev@example.com', 'max plan'), $billedSubscriptionHolder)->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), new BufferedOutput()));

        self::assertSame('your Claude subscription (max plan)', $billedSubscriptionHolder->billedSubscription());
    }

    /**
     * @throws RunRefusedException
     */
    #[DataProvider('accountsAndTheSubscriptionReportsName')]
    public function test_it_hands_the_reports_only_the_subscription_it_knows_it_bills(CliAgentAccount $cliAgentAccount, ?string $billedSubscription): void
    {
        $billedSubscriptionHolder = new BilledSubscriptionHolder();

        $this->guard($cliAgentAccount, $billedSubscriptionHolder)->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), new BufferedOutput()));

        self::assertSame($billedSubscription, $billedSubscriptionHolder->billedSubscription());
    }

    /**
     * @throws RunRefusedException
     */
    public function test_an_unattended_run_hands_the_reports_the_plan_it_bills(): void
    {
        $billedSubscriptionHolder = new BilledSubscriptionHolder();

        $this->guard(CliAgentAccount::subscription('max plan, dev@example.com', 'max plan'), $billedSubscriptionHolder)->assertUnattendedRunPermitted(new NullLogger());

        self::assertSame('your Claude subscription (max plan)', $billedSubscriptionHolder->billedSubscription());
    }

    /**
     * @return iterable<string, array{CliAgentAccount, ?string}>
     */
    public static function accountsAndTheSubscriptionReportsName(): iterable
    {
        yield 'no plan' => [CliAgentAccount::subscription(null), 'your Claude subscription'];
        yield 'unknown account' => [CliAgentAccount::unknown('"claude auth status" failed'), null];
    }

    public function test_it_says_in_its_header_which_api_key_it_refuses_to_bill(): void
    {
        $bufferedOutput = new BufferedOutput();

        try {
            $this->guard(CliAgentAccount::apiKey('apiKeyHelper', 'Stop it.'))->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), $bufferedOutput));
        } catch (RunRefusedException) {
            self::assertStringContainsString('Billing: the API key in apiKeyHelper, not your Claude subscription', (string) preg_replace('/\s+/', ' ', $bufferedOutput->fetch()));

            return;
        }

        self::fail('The guard let a run start that an API key would bill.');
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_refuses_to_start_while_the_cli_is_not_logged_in(): void
    {
        $this->expectExceptionObject(RunRefusedException::because('Run "claude auth login" to log the Claude Code CLI in to your Claude subscription before an audit.'));

        $this->guard(CliAgentAccount::notLoggedIn())->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), new BufferedOutput()));
    }

    /**
     * @throws RunRefusedException
     */
    public function test_a_refused_budget_stops_the_run_before_the_cli_is_asked(): void
    {
        $unpricedModelBudgetGuard = self::createStub(UnpricedModelBudgetGuardInterface::class);
        $unpricedModelBudgetGuard->method('permitsRun')->willReturn(false);
        $cliAgentAccountProbe = $this->createMock(CliAgentAccountProbeInterface::class);
        $cliAgentAccountProbe->expects(self::never())->method('probe');

        self::assertFalse((new SubscriptionAccountGuard($unpricedModelBudgetGuard, new ClaudeCodeSubscriptionCli(), null, $cliAgentAccountProbe))->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), new BufferedOutput())));
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_asks_the_cli_the_configuration_names(): void
    {
        $unpricedModelBudgetGuard = self::createStub(UnpricedModelBudgetGuardInterface::class);
        $unpricedModelBudgetGuard->method('permitsRun')->willReturn(true);
        $cliAgentAccountProbe = $this->createMock(CliAgentAccountProbeInterface::class);
        $cliAgentAccountProbe->expects(self::once())->method('probe')->with('claudecode', '/opt/claude/bin/claude')->willReturn(CliAgentAccount::subscription(null));

        (new SubscriptionAccountGuard($unpricedModelBudgetGuard, new ClaudeCodeSubscriptionCli(), '/opt/claude/bin/claude', $cliAgentAccountProbe))->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), new BufferedOutput()));
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_leaves_the_unenforceable_budget_warning_to_the_guard_it_wraps(): void
    {
        $logger = new NullLogger();
        $unpricedModelBudgetGuard = $this->createMock(UnpricedModelBudgetGuardInterface::class);
        $unpricedModelBudgetGuard->expects(self::once())->method('assertUnattendedRunPermitted')->with($logger);
        $cliAgentAccountProbe = self::createStub(CliAgentAccountProbeInterface::class);
        $cliAgentAccountProbe->method('probe')->willReturn(CliAgentAccount::subscription(null));

        (new SubscriptionAccountGuard($unpricedModelBudgetGuard, new ClaudeCodeSubscriptionCli(), null, $cliAgentAccountProbe))->assertUnattendedRunPermitted($logger);
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_refuses_to_start_when_an_api_key_would_bill_in_place_of_the_subscription(): void
    {
        $this->expectExceptionObject(RunRefusedException::because('The Claude Code CLI bills the API key in apiKeyHelper, not your Claude subscription. Stop it.'));

        $this->guard(CliAgentAccount::apiKey('apiKeyHelper', 'Stop it.'))->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), new BufferedOutput()));
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_warns_and_lets_the_audit_run_when_the_cli_cannot_tell_which_account_it_bills(): void
    {
        $bufferedOutput = new BufferedOutput();

        $permitted = $this->guard(CliAgentAccount::unknown('"claude auth status" failed'))->permitsRun(new ArrayInput([]), new SymfonyStyle(new ArrayInput([]), $bufferedOutput));

        self::assertSame([true, true], [$permitted, str_contains((string) preg_replace('/\s+/', ' ', $bufferedOutput->fetch()), '[WARNING] Run "claude auth status" to see which account the Claude Code CLI bills.')]);
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_refuses_an_unattended_run_while_the_cli_is_not_logged_in(): void
    {
        $this->expectExceptionObject(RunRefusedException::because('Run "claude auth login" to log the Claude Code CLI in to your Claude subscription before an audit.'));

        $this->guard(CliAgentAccount::notLoggedIn())->assertUnattendedRunPermitted(new NullLogger());
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_logs_and_lets_an_unattended_run_start_when_the_cli_cannot_tell_which_account_it_bills(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        $this->guard(CliAgentAccount::unknown('"claude auth status" failed'))->assertUnattendedRunPermitted($warningCollectingLogger);

        self::assertCount(1, $warningCollectingLogger->warnings);
        self::assertStringContainsString('Run "claude auth status" to see which account the Claude Code CLI bills.', $warningCollectingLogger->warnings[0][0]);
    }

    /**
     * @throws RunRefusedException
     */
    public function test_it_logs_nothing_for_an_unattended_run_the_subscription_bills(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        $this->guard(CliAgentAccount::subscription('max plan'))->assertUnattendedRunPermitted($warningCollectingLogger);

        self::assertSame([], $warningCollectingLogger->warnings);
    }

    private function guard(CliAgentAccount $cliAgentAccount, BilledSubscriptionHolder $billedSubscriptionHolder = new BilledSubscriptionHolder()): SubscriptionAccountGuard
    {
        $unpricedModelBudgetGuard = self::createStub(UnpricedModelBudgetGuardInterface::class);
        $unpricedModelBudgetGuard->method('permitsRun')->willReturn(true);
        $cliAgentAccountProbe = self::createStub(CliAgentAccountProbeInterface::class);
        $cliAgentAccountProbe->method('probe')->willReturn($cliAgentAccount);

        return new SubscriptionAccountGuard($unpricedModelBudgetGuard, new ClaudeCodeSubscriptionCli(), null, $cliAgentAccountProbe, $billedSubscriptionHolder);
    }
}
