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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Override;
use Symfony\Component\Process\Process;

/**
 * The Codex CLI, on a ChatGPT subscription. Reads its account from
 * `codex login status`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CodexSubscriptionCli implements SubscriptionCliInterface
{
    private const string CHATGPT_LOGIN = 'Logged in using ChatGPT';

    private const string API_KEY_LOGIN = 'Logged in using an API key';

    private const string LOGGED_OUT = 'Not logged in';

    private const string API_KEY_VARIABLE = 'CODEX_API_KEY';

    #[Override]
    public function platform(): string
    {
        return 'codex';
    }

    #[Override]
    public function subscription(): string
    {
        return 'your ChatGPT subscription';
    }

    #[Override]
    public function suggestedReviewerModel(): string
    {
        return 'gpt-6-luna';
    }

    #[Override]
    public function loginCommand(): string
    {
        return 'codex login';
    }

    #[Override]
    public function statusCommand(): string
    {
        return 'codex login status';
    }

    #[Override]
    public function subscriptionOnlyOptions(): array
    {
        return [];
    }

    #[Override]
    public function billingVariables(): array
    {
        return [self::API_KEY_VARIABLE, 'OPENAI_API_KEY'];
    }

    #[Override]
    public function account(?string $cliBinary, CliStatusRun $cliStatusRun): CliAgentAccount
    {
        $command = [$cliBinary ?? 'codex', 'login', 'status'];
        $process = $cliStatusRun->run($command, $this->billingVariables());
        if (!$process instanceof Process) {
            return CliAgentAccount::failedCommand($command);
        }

        $answer = \sprintf('%s%s', $process->getOutput(), $process->getErrorOutput());

        return match (true) {
            str_contains($answer, self::CHATGPT_LOGIN) => CliAgentAccount::subscription(null),
            str_contains($answer, self::API_KEY_LOGIN) => CliAgentAccount::apiKey('the Codex login', 'Run "codex logout", then "codex login" with your ChatGPT account, to run the audit on the subscription.'),
            str_contains($answer, self::LOGGED_OUT) => CliAgentAccount::notLoggedIn(),
            !$process->isSuccessful() => CliAgentAccount::failedCommand($command),
            default => CliAgentAccount::unreadableAnswer($command),
        };
    }
}
