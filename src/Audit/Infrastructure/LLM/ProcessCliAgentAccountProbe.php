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

/**
 * Asks the subscription CLI the provider names which account its calls bill,
 * by running its status command.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProcessCliAgentAccountProbe implements CliAgentAccountProbeInterface
{
    private CliStatusRun $cliStatusRun;

    private SubscriptionClis $subscriptionClis;

    public function __construct(
        float $timeoutSeconds = 20.0,
        ?SubscriptionClis $subscriptionClis = null,
    ) {
        $this->cliStatusRun = new CliStatusRun($timeoutSeconds);
        $this->subscriptionClis = $subscriptionClis ?? SubscriptionClis::bundled();
    }

    #[Override]
    public function probe(string $agent, ?string $cliBinary): CliAgentAccount
    {
        $subscriptionCli = $this->subscriptionClis->of($agent);

        return $subscriptionCli instanceof SubscriptionCliInterface
            ? $subscriptionCli->account($cliBinary, $this->cliStatusRun)
            : CliAgentAccount::unknown(\sprintf('no subscription CLI is named %s', $agent));
    }
}
