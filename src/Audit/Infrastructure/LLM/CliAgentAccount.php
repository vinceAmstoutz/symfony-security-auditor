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

/**
 * The account a coding agent's CLI bills, as the CLI itself reports it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CliAgentAccount
{
    /**
     * @param ?string $detail the plan and account of a subscription, what holds the API key that bills instead, or why the CLI could not tell
     * @param ?string $plan   the plan of a subscription alone, without the account that could identify a person
     */
    private function __construct(
        public CliAgentBilling $billing,
        public ?string $detail,
        public ?string $remedy = null,
        public ?string $plan = null,
    ) {}

    public static function subscription(?string $account, ?string $plan = null): self
    {
        return new self(CliAgentBilling::Subscription, $account, plan: $plan);
    }

    /**
     * @param string $source where the API key that bills sits, such as `ANTHROPIC_API_KEY`
     * @param string $remedy how to bill the subscription instead
     */
    public static function apiKey(string $source, string $remedy): self
    {
        return new self(CliAgentBilling::ApiKey, $source, $remedy);
    }

    public static function notLoggedIn(): self
    {
        return new self(CliAgentBilling::NotLoggedIn, null);
    }

    public static function unknown(string $reason): self
    {
        return new self(CliAgentBilling::Unknown, $reason);
    }

    /**
     * @param list<string> $command
     */
    public static function failedCommand(array $command): self
    {
        return self::unknown(\sprintf('"%s" failed', implode(' ', $command)));
    }

    /**
     * @param list<string> $command
     */
    public static function unreadableAnswer(array $command): self
    {
        return self::unknown(\sprintf('"%s" answered no status this version can read', implode(' ', $command)));
    }
}
