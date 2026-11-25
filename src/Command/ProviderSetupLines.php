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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentBilling;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionCliInterface;

/**
 * The provider and models an audit runs with, as `auth:status` and `doctor`
 * describe them.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProviderSetupLines
{
    /**
     * @return list<array<string, string>> one definition-list row each
     */
    public static function of(ConfiguredProvider $configuredProvider, ?SubscriptionCliInterface $subscriptionCli, ?CliAgentAccount $cliAgentAccount): array
    {
        $lines = [['Provider' => self::providerName($configuredProvider->name)]];
        if (null !== $configuredProvider->model) {
            $lines[] = ['Model' => self::modelLine($configuredProvider->model, $configuredProvider)];
        }

        $lines[] = ['Billing' => $subscriptionCli instanceof SubscriptionCliInterface && $cliAgentAccount instanceof CliAgentAccount ? self::subscriptionBilling($subscriptionCli, $cliAgentAccount) : self::apiBilling($configuredProvider)];

        return $lines;
    }

    /**
     * Returns what the user must hear before an audit runs: the CLI bills an
     * API key in place of the subscription, is not logged in or cannot tell.
     * Null when nothing is wrong.
     */
    public static function warningFor(?SubscriptionCliInterface $subscriptionCli, ?CliAgentAccount $cliAgentAccount): ?string
    {
        if (!$subscriptionCli instanceof SubscriptionCliInterface) {
            return null;
        }

        $cliName = ProviderNames::ofPlatform($subscriptionCli->platform());

        return match ($cliAgentAccount?->billing) {
            CliAgentBilling::ApiKey => \sprintf('%s bills %s, not %s. %s', ucfirst($cliName), self::apiKeySource($cliAgentAccount), $subscriptionCli->subscription(), $cliAgentAccount->remedy),
            CliAgentBilling::NotLoggedIn => \sprintf('Run "%s" to log %s in to %s before an audit.', $subscriptionCli->loginCommand(), $cliName, $subscriptionCli->subscription()),
            CliAgentBilling::Unknown => \sprintf('Run "%s" to see which account %s bills.', $subscriptionCli->statusCommand(), $cliName),
            default => null,
        };
    }

    private static function providerName(string $provider): string
    {
        $name = ProviderNames::of($provider);

        return $name === $provider ? ucfirst(ProviderNames::ofPlatform($provider)) : $name;
    }

    public static function subscriptionBilling(SubscriptionCliInterface $subscriptionCli, CliAgentAccount $cliAgentAccount): string
    {
        $subscription = $subscriptionCli->subscription();

        return match (true) {
            CliAgentBilling::ApiKey === $cliAgentAccount->billing => \sprintf('%s, not %s', self::apiKeySource($cliAgentAccount), $subscription),
            CliAgentBilling::NotLoggedIn === $cliAgentAccount->billing => \sprintf('nothing yet: %s is not logged in', ProviderNames::ofPlatform($subscriptionCli->platform())),
            CliAgentBilling::Unknown === $cliAgentAccount->billing => \sprintf('unknown: %s', $cliAgentAccount->detail),
            null === $cliAgentAccount->detail => $subscription,
            default => \sprintf('%s (%s)', $subscription, $cliAgentAccount->detail),
        };
    }

    private static function apiBilling(ConfiguredProvider $configuredProvider): string
    {
        return match (true) {
            !$configuredProvider->takesApiKey => \sprintf('nothing per call: %s takes no API key', ProviderNames::ofPlatform($configuredProvider->name)),
            null !== $configuredProvider->apiKeyVariable => \sprintf('per call, to the API key %s holds', $configuredProvider->apiKeyVariable),
            default => 'per call, to the API key the configuration holds',
        };
    }

    private static function apiKeySource(CliAgentAccount $cliAgentAccount): string
    {
        return \sprintf('the API key in %s', $cliAgentAccount->detail);
    }

    private static function modelLine(string $model, ConfiguredProvider $configuredProvider): string
    {
        $parts = [$model];
        if (null !== $configuredProvider->reviewerModel) {
            $parts[] = \sprintf('reviewed by %s', $configuredProvider->reviewerModel);
        }

        if (null !== $configuredProvider->effort) {
            $parts[] = \sprintf('effort %s', $configuredProvider->effort);
        }

        return implode(', ', $parts);
    }
}
