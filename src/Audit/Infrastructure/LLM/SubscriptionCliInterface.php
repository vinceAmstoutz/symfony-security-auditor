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
 * A coding agent's CLI that runs the audit on its vendor's subscription.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface SubscriptionCliInterface
{
    /**
     * The `provider:` the configuration selects it by, such as `claudecode`.
     */
    public function platform(): string;

    /**
     * The subscription it bills, such as "your Claude subscription".
     */
    public function subscription(): string;

    /**
     * The model `init` suggests to review the findings, the lightest one the
     * subscription runs.
     */
    public function suggestedReviewerModel(): string;

    /**
     * The command that logs the CLI in to the subscription.
     */
    public function loginCommand(): string;

    /**
     * The command that shows which account the CLI bills.
     */
    public function statusCommand(): string;

    /**
     * The options that keep the CLI from billing anything but the
     * subscription, in the spelling its bridge reads.
     *
     * @return array<string, mixed>
     */
    public function subscriptionOnlyOptions(): array;

    /**
     * The environment variables that would make the CLI bill an API key or a
     * cloud account in place of the subscription, removed from the
     * environment it runs in.
     *
     * @return list<string>
     */
    public function billingVariables(): array;

    /**
     * @param ?string $cliBinary the CLI the configuration names, else the one on the `PATH`
     */
    public function account(?string $cliBinary, CliStatusRun $cliStatusRun): CliAgentAccount;
}
