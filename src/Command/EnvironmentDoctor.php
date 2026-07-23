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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

/**
 * Preflight for the standalone binary: confirms the configuration resolves
 * (file present, valid, provider selected, API-key variable set), the provider
 * bridge is installed *and actually boots the audit for the configured
 * provider* (a leftover bridge from a previously configured provider passes a
 * file-existence check but not a boot), and `composer` is reachable — the
 * prerequisites for a successful audit run. The boot probe is skipped while
 * the configuration check fails, so a config problem is reported once, by the
 * check that owns it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EnvironmentDoctor implements EnvironmentDoctorInterface
{
    private const string BRIDGE_AUTOLOAD_RELATIVE_PATH = 'vendor/autoload.php';

    public function __construct(
        private StandaloneConfigLoader $standaloneConfigLoader,
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private ComposerAvailabilityCheckerInterface $composerAvailabilityChecker,
        private AuditPreflightInterface $auditPreflight,
    ) {}

    /**
     * @return list<DoctorCheckResult>
     */
    #[Override]
    public function diagnose(): array
    {
        $doctorCheckResult = $this->configurationCheck();

        return [
            $doctorCheckResult,
            $this->bridgeCheck(DoctorCheckStatus::Ok === $doctorCheckResult->status),
            $this->composerCheck(),
        ];
    }

    private function configurationCheck(): DoctorCheckResult
    {
        try {
            $this->standaloneConfigLoader->load();
        } catch (MissingPlatformException) {
            return new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, 'No provider is configured — run "init".');
        } catch (MissingEnvironmentVariableException $missingEnvironmentVariableException) {
            return new DoctorCheckResult('API key', DoctorCheckStatus::Failure, $missingEnvironmentVariableException->getMessage());
        } catch (MalformedProjectConfigException $malformedProjectConfigException) {
            return new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, $malformedProjectConfigException->getMessage());
        } catch (UnresolvableConfigPathException $unresolvableConfigPathException) {
            return new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, $unresolvableConfigPathException->getMessage());
        }

        return new DoctorCheckResult('Configuration', DoctorCheckStatus::Ok, 'Config resolves and the API-key variable is set.');
    }

    private function bridgeCheck(bool $configurationResolves): DoctorCheckResult
    {
        try {
            $bridgeAutoloadFile = \sprintf('%s/%s', $this->xdgConfigPathResolver->dataDir(), self::BRIDGE_AUTOLOAD_RELATIVE_PATH);
        } catch (UnresolvableConfigPathException $unresolvableConfigPathException) {
            return new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, $unresolvableConfigPathException->getMessage());
        }

        if (!is_file($bridgeAutoloadFile)) {
            return new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, 'Not installed — run "init" to download it.');
        }

        if (!$configurationResolves) {
            return new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Ok, 'Installed.');
        }

        $failureReason = $this->auditPreflight->failureReason();

        return null === $failureReason
            ? new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Ok, 'Installed and the audit boots with it.')
            : new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, \sprintf('Installed, but the audit cannot start with it: %s', $failureReason));
    }

    private function composerCheck(): DoctorCheckResult
    {
        return $this->composerAvailabilityChecker->isAvailable()
            ? new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.')
            : new DoctorCheckResult('Composer', DoctorCheckStatus::Warning, 'Not found — needed only to run "init" or switch providers, not to audit.');
    }
}
