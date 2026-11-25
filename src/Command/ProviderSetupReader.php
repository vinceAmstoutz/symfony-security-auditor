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

use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;

/**
 * Reads the provider setup when a command runs, never sooner, since reading
 * a subscription's account starts its CLI.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProviderSetupReader
{
    public function __construct(
        private ConfiguredCredentialVariable $configuredCredentialVariable,
        private ?CliAgentAccountProbeInterface $cliAgentAccountProbe,
    ) {}

    /**
     * Lists the provider, models and billed account, then any warning about
     * them. Returns null, printing nothing, when no provider is configured.
     */
    public function report(SymfonyStyle $symfonyStyle): ?ProviderSetup
    {
        $providerSetup = ProviderSetup::read($this->configuredCredentialVariable, $this->cliAgentAccountProbe);
        if (!$providerSetup instanceof ProviderSetup) {
            return null;
        }

        $symfonyStyle->definitionList(...$providerSetup->rows());
        $warning = $providerSetup->warning();
        if (null !== $warning) {
            $symfonyStyle->warning($warning);
        }

        return $providerSetup;
    }
}
