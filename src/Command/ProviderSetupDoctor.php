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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;

/**
 * Adds to the other checks the provider, models and billed account an audit
 * runs with: a warning when the subscription's CLI bills an API key, a
 * failure when it is not logged in.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProviderSetupDoctor implements EnvironmentDoctorInterface
{
    private const string PROVIDER_CHECK = 'Provider';

    public function __construct(
        private EnvironmentDoctorInterface $environmentDoctor,
        private ConfiguredCredentialVariable $configuredCredentialVariable,
        private CliAgentAccountProbeInterface $cliAgentAccountProbe,
    ) {}

    #[Override]
    public function diagnose(): array
    {
        $results = $this->environmentDoctor->diagnose();
        $providerSetup = ProviderSetup::read($this->configuredCredentialVariable, $this->cliAgentAccountProbe);
        if ($providerSetup instanceof ProviderSetup) {
            $results[] = $this->providerResult($providerSetup);
        }

        return $results;
    }

    private function providerResult(ProviderSetup $providerSetup): DoctorCheckResult
    {
        $warning = $providerSetup->warning();

        return match (true) {
            null === $warning => new DoctorCheckResult(self::PROVIDER_CHECK, DoctorCheckStatus::Ok, $providerSetup->summary()),
            $providerSetup->isLoggedOut() => new DoctorCheckResult(self::PROVIDER_CHECK, DoctorCheckStatus::Failure, \sprintf('%s %s', $providerSetup->summary(), $warning)),
            default => new DoctorCheckResult(self::PROVIDER_CHECK, DoctorCheckStatus::Warning, \sprintf('%s %s', $providerSetup->summary(), $warning)),
        };
    }
}
