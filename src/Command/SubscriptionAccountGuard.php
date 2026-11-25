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

use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentBilling;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionCliInterface;

/**
 * Names in the audit header the account the subscription's CLI bills and
 * refuses to start while it would bill an API key in place of the
 * subscription or is logged out. Warns when the CLI cannot tell.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SubscriptionAccountGuard implements UnpricedModelBudgetGuardInterface
{
    public function __construct(
        private UnpricedModelBudgetGuardInterface $unpricedModelBudgetGuard,
        private SubscriptionCliInterface $subscriptionCli,
        private ?string $cliBinary,
        private CliAgentAccountProbeInterface $cliAgentAccountProbe,
    ) {}

    #[Override]
    public function permitsRun(InputInterface $input, SymfonyStyle $symfonyStyle): bool
    {
        if (!$this->unpricedModelBudgetGuard->permitsRun($input, $symfonyStyle)) {
            return false;
        }

        $cliAgentAccount = $this->cliAgentAccountProbe->probe($this->subscriptionCli->platform(), $this->cliBinary);
        $errorStyle = $symfonyStyle->getErrorStyle();
        $errorStyle->writeln(\sprintf(' Billing: %s', ProviderSetupLines::subscriptionBilling($this->subscriptionCli, $cliAgentAccount)));

        $warning = ProviderSetupLines::warningFor($this->subscriptionCli, $cliAgentAccount);
        if (null === $warning) {
            return true;
        }

        if (\in_array($cliAgentAccount->billing, [CliAgentBilling::NotLoggedIn, CliAgentBilling::ApiKey], true)) {
            $errorStyle->error($warning);

            return false;
        }

        $errorStyle->warning($warning);

        return true;
    }

    #[Override]
    public function warnWhenBudgetCannotBeEnforced(LoggerInterface $logger): void
    {
        $this->unpricedModelBudgetGuard->warnWhenBudgetCannotBeEnforced($logger);
    }
}
