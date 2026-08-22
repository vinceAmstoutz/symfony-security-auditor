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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigPlatformOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigScanOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;

use function Symfony\Component\String\b;

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
        private ModelsDevPricingProvider $modelsDevPricingProvider,
        private string $pricingCatalogPackage = ModelsDevPricingProvider::CATALOG_PACKAGE,
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
            $this->pricingCatalogCheck(),
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
        } catch (ProjectConfigPlatformOverrideException $projectConfigPlatformOverrideException) {
            return new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, $projectConfigPlatformOverrideException->getMessage());
        } catch (ProjectConfigScanOverrideException $projectConfigScanOverrideException) {
            return new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, $projectConfigScanOverrideException->getMessage());
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
            : new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, $this->bootFailureDetail($failureReason));
    }

    /**
     * The reason is an arbitrary `Throwable` message from the boot probe and
     * may contain non-UTF-8 bytes (paths, quoted file contents), so it is
     * handled byte-safely — `u()` would throw on it and mask the diagnosis.
     */
    private function bootFailureDetail(string $failureReason): string
    {
        $reason = b($failureReason)->trim()->toString();

        return '' === $reason
            ? 'Installed, but the audit cannot start with it (the boot failed without an error message).'
            : \sprintf('Installed, but the audit cannot start with it: %s', $reason);
    }

    private function composerCheck(): DoctorCheckResult
    {
        return $this->composerAvailabilityChecker->isAvailable()
            ? new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.')
            : new DoctorCheckResult('Composer', DoctorCheckStatus::Warning, 'Not found — needed only to run "init" or switch providers, not to audit.');
    }

    /**
     * Names the catalog file actually in use rather than only the packaged
     * version: once `self-update` has refreshed the catalog, the run reads an
     * override and reporting the package version alone would describe a file
     * the audit is not pricing from.
     */
    private function pricingCatalogCheck(): DoctorCheckResult
    {
        $catalogPath = $this->modelsDevPricingProvider->effectiveCatalogPath();

        if (null === $catalogPath || !is_file($catalogPath)) {
            return new DoctorCheckResult('Pricing catalog', DoctorCheckStatus::Warning, \sprintf('%s not found — cost figures will show $0.00.', $this->pricingCatalogPackage));
        }

        return new DoctorCheckResult('Pricing catalog', DoctorCheckStatus::Ok, $this->pricingCatalogDetail($catalogPath));
    }

    /**
     * The package version describes the packaged catalog and nothing else. A
     * `self-update` refresh writes an override whose contents come from
     * upstream `main` at refresh time, so stamping the bundled version onto it
     * would assert a version that file does not have.
     */
    private function pricingCatalogDetail(string $catalogPath): string
    {
        if ($catalogPath !== $this->modelsDevPricingProvider->packagedCatalogPath()) {
            return \sprintf('refreshed catalog (%s); bundled %s unused.', $catalogPath, $this->pricingCatalogPackage);
        }

        return \sprintf('%s %s (%s).', $this->pricingCatalogPackage, (new ReportPackage($this->pricingCatalogPackage))->version(), $catalogPath);
    }
}
