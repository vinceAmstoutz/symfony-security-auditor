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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ClaudeCodeSubscriptionCli;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentBilling;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CodexSubscriptionCli;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionCliInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionClis;

/**
 * The provider, models and billed account an audit runs with, the account
 * of a subscription read from its CLI.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProviderSetup
{
    private const string PROVIDER_LABEL = 'Provider';

    private function __construct(
        private ConfiguredProvider $configuredProvider,
        private ?SubscriptionCliInterface $subscriptionCli,
        private ?CliAgentAccount $cliAgentAccount,
    ) {}

    /**
     * Returns null when the configuration names no provider.
     */
    public static function read(ConfiguredCredentialVariable $configuredCredentialVariable, ?CliAgentAccountProbeInterface $cliAgentAccountProbe, SubscriptionClis $subscriptionClis = new SubscriptionClis(new ClaudeCodeSubscriptionCli(), new CodexSubscriptionCli())): ?self
    {
        $configuredProvider = $configuredCredentialVariable->provider();
        if (!$configuredProvider instanceof ConfiguredProvider) {
            return null;
        }

        $subscriptionCli = $subscriptionClis->of($configuredProvider->name);
        $cliAgentAccount = $subscriptionCli instanceof SubscriptionCliInterface
            ? $cliAgentAccountProbe?->probe($configuredProvider->name, $configuredProvider->cliBinary)
            : null;

        return new self($configuredProvider, $subscriptionCli, $cliAgentAccount);
    }

    /**
     * @return list<array<string, string>> one definition-list row each
     */
    public function rows(): array
    {
        return ProviderSetupLines::of($this->configuredProvider, $this->subscriptionCli, $this->cliAgentAccount);
    }

    public function summary(): string
    {
        $sentences = [];
        foreach ($this->rows() as $row) {
            foreach ($row as $label => $value) {
                $sentences[] = self::PROVIDER_LABEL === $label ? \sprintf('%s.', $value) : \sprintf('%s: %s.', $label, $value);
            }
        }

        return implode(' ', $sentences);
    }

    public function warning(): ?string
    {
        return ProviderSetupLines::warningFor($this->subscriptionCli, $this->cliAgentAccount);
    }

    public function runsOnACli(): bool
    {
        return $this->cliAgentAccount instanceof CliAgentAccount;
    }

    public function isLoggedOut(): bool
    {
        return CliAgentBilling::NotLoggedIn === $this->cliAgentAccount?->billing;
    }
}
