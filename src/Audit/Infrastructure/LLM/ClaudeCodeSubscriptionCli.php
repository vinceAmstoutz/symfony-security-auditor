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

use JsonException;
use Override;
use Symfony\Component\Process\Process;

/**
 * The Claude Code CLI, on a Claude subscription. Reads its account from
 * `claude auth status --json`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ClaudeCodeSubscriptionCli implements SubscriptionCliInterface
{
    private const string API_KEY_VARIABLE = 'ANTHROPIC_API_KEY';

    private const string API_KEY_HELPER = 'apiKeyHelper';

    private const string CONFIG_DIRECTORY_VARIABLE = 'CLAUDE_CONFIG_DIR';

    #[Override]
    public function platform(): string
    {
        return 'claudecode';
    }

    #[Override]
    public function subscription(): string
    {
        return 'your Claude subscription';
    }

    #[Override]
    public function loginCommand(): string
    {
        return 'claude auth login';
    }

    #[Override]
    public function statusCommand(): string
    {
        return 'claude auth status';
    }

    #[Override]
    public function subscriptionOnlyOptions(): array
    {
        return ['setting_sources' => ''];
    }

    #[Override]
    public function billingVariables(): array
    {
        return [self::API_KEY_VARIABLE, 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY'];
    }

    #[Override]
    public function account(?string $cliBinary, CliStatusRun $cliStatusRun): CliAgentAccount
    {
        $command = [$cliBinary ?? 'claude', 'auth', 'status'];
        $process = $cliStatusRun->run([...$command, '--json'], $this->billingVariables());
        if (!$process instanceof Process) {
            return CliAgentAccount::failedCommand($command);
        }

        $status = $this->decoded($process->getOutput());
        if (null === $status) {
            return $process->isSuccessful() ? CliAgentAccount::unreadableAnswer($command) : CliAgentAccount::failedCommand($command);
        }

        return $this->ignoresHelperOf($status, $command, $cliStatusRun) ? $this->accountWithoutHelper($status) : $this->accountIn($status);
    }

    /**
     * Whether the `apiKeyHelper` source comes from a settings file: the audit
     * loads no settings file, so only one of managed settings bills in its
     * place.
     *
     * @param array<array-key, mixed> $status
     * @param list<string>            $command
     */
    private function ignoresHelperOf(array $status, array $command, CliStatusRun $cliStatusRun): bool
    {
        return self::API_KEY_HELPER === ($status['apiKeySource'] ?? null) && !$this->helperOutlivesSettingsFiles($command, $cliStatusRun);
    }

    /**
     * The account the audit bills once it ignores the `apiKeyHelper` of a
     * settings file. Unknown for a login that names no subscription plan,
     * which that helper may be all of.
     *
     * @param array<array-key, mixed> $status
     */
    private function accountWithoutHelper(array $status): CliAgentAccount
    {
        unset($status['apiKeySource']);
        if (true === ($status['loggedIn'] ?? null) && !\is_string($status['subscriptionType'] ?? null)) {
            return CliAgentAccount::unknown(\sprintf('"%s" names no subscription plan besides an apiKeyHelper the audit ignores', $this->statusCommand()));
        }

        return $this->accountIn($status);
    }

    /**
     * @param list<string> $command
     */
    private function helperOutlivesSettingsFiles(array $command, CliStatusRun $cliStatusRun): bool
    {
        $emptyConfigDirectory = new CliAgentWorkingDirectory();
        $process = $cliStatusRun->run([...$command, '--json'], $this->billingVariables(), [self::CONFIG_DIRECTORY_VARIABLE => $emptyConfigDirectory->path], $emptyConfigDirectory->path);
        unset($emptyConfigDirectory);

        $status = $process instanceof Process ? $this->decoded($process->getOutput()) : null;

        return null === $status || self::API_KEY_HELPER === ($status['apiKeySource'] ?? null);
    }

    /**
     * @return ?array<array-key, mixed>
     */
    private function decoded(string $output): ?array
    {
        try {
            $status = json_decode($output, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        return \is_array($status) ? $status : null;
    }

    /**
     * @param array<array-key, mixed> $status
     */
    private function accountIn(array $status): CliAgentAccount
    {
        if (true !== ($status['loggedIn'] ?? null)) {
            return CliAgentAccount::notLoggedIn();
        }

        $apiKeySource = $status['apiKeySource'] ?? null;
        if (\is_string($apiKeySource) && 'none' !== $apiKeySource) {
            return CliAgentAccount::apiKey($apiKeySource, $this->remedy($apiKeySource));
        }

        $account = array_filter([
            \is_string($status['subscriptionType'] ?? null) ? \sprintf('%s plan', $status['subscriptionType']) : null,
            \is_string($status['email'] ?? null) ? $status['email'] : null,
        ], static fn (?string $part): bool => null !== $part);

        return CliAgentAccount::subscription([] === $account ? null : implode(', ', $account));
    }

    private function remedy(string $apiKeySource): string
    {
        return match ($apiKeySource) {
            self::API_KEY_VARIABLE => \sprintf('Unset %s to run the audit on the subscription.', $apiKeySource),
            self::API_KEY_HELPER => 'Managed settings give the Claude Code CLI this apiKeyHelper: ask whoever manages them to remove it to run the audit on the subscription.',
            default => \sprintf('Stop the Claude Code CLI using %s (see "claude auth status") to run the audit on the subscription.', $apiKeySource),
        };
    }
}
