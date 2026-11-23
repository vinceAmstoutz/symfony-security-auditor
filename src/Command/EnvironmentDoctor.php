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
use Symfony\Component\Console\Formatter\OutputFormatter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeTree;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\StaleBridgeTreeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigPlatformOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigScanOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigUserOnlyKeyException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsupportedEnvPlaceholderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;

use function Symfony\Component\String\b;

/**
 * Preflight for the standalone binary: the configuration resolves, the
 * provider bridge is installed and boots the audit for the configured
 * provider, `composer` is reachable and the pricing catalog is found. The boot
 * probe is skipped while the configuration check fails.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class EnvironmentDoctor implements EnvironmentDoctorInterface
{
    private const string CONFIGURATION_CHECK = 'Configuration';

    private const string API_KEY_CHECK = 'API key';

    private const string BRIDGE_CHECK = 'Provider bridge';

    /**
     * @param ?string $bundledAiPlatformVersion the `symfony/ai-platform` release the binary bundles, which the bridge tree must hold too
     */
    public function __construct(
        private StandaloneConfigLoader $standaloneConfigLoader,
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private ComposerAvailabilityCheckerInterface $composerAvailabilityChecker,
        private AuditPreflightInterface $auditPreflight,
        private ModelsDevPricingProvider $modelsDevPricingProvider,
        private string $pricingCatalogPackage = ModelsDevPricingProvider::CATALOG_PACKAGE,
        private ?string $bundledAiPlatformVersion = null,
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
            $standaloneConfig = $this->standaloneConfigLoader->load();
        } catch (MissingPlatformException) {
            return new DoctorCheckResult(self::CONFIGURATION_CHECK, DoctorCheckStatus::Failure, 'No provider is configured — run "init".');
        } catch (MissingEnvironmentVariableException $missingEnvironmentVariableException) {
            return new DoctorCheckResult($missingEnvironmentVariableException->concernsCredential ? self::API_KEY_CHECK : self::CONFIGURATION_CHECK, DoctorCheckStatus::Failure, $missingEnvironmentVariableException->getMessage());
        } catch (UnreadableCredentialFileException|UnreadableCredentialStoreException $credentialResolutionFailure) {
            return new DoctorCheckResult(self::API_KEY_CHECK, DoctorCheckStatus::Failure, $credentialResolutionFailure->getMessage());
        } catch (MalformedProjectConfigException|ProjectConfigPlatformOverrideException|ProjectConfigScanOverrideException|ProjectConfigUserOnlyKeyException|UnsupportedEnvPlaceholderException $configurationFailure) {
            return new DoctorCheckResult(self::CONFIGURATION_CHECK, DoctorCheckStatus::Failure, $configurationFailure->getMessage());
        } catch (UnresolvableConfigPathException $unresolvableConfigPathException) {
            return new DoctorCheckResult(self::CONFIGURATION_CHECK, DoctorCheckStatus::Failure, $unresolvableConfigPathException->getMessage());
        }

        return new DoctorCheckResult(self::CONFIGURATION_CHECK, DoctorCheckStatus::Ok, $this->resolvedConfigurationDetail($standaloneConfig));
    }

    /**
     * Names the API key that resolved by its masked preview and fingerprint.
     */
    private function resolvedConfigurationDetail(StandaloneConfig $standaloneConfig): string
    {
        $credentialIdentity = $standaloneConfig->platform->credentialIdentity();

        return $credentialIdentity instanceof CredentialIdentity
            ? \sprintf('Config resolves and an API key is available: %s (%s). Run "%s" to see where it comes from.', $credentialIdentity->maskedPreview, $credentialIdentity->fingerprint, AuthStatusCommand::NAME)
            : 'Config resolves; the configured platform needs no API key.';
    }

    private function bridgeCheck(bool $configurationResolves): DoctorCheckResult
    {
        try {
            $bridgeTree = new BridgeTree($this->xdgConfigPathResolver->dataDir(), $this->bundledAiPlatformVersion);
        } catch (UnresolvableConfigPathException $unresolvableConfigPathException) {
            return new DoctorCheckResult(self::BRIDGE_CHECK, DoctorCheckStatus::Failure, $unresolvableConfigPathException->getMessage());
        }

        if (!$bridgeTree->isInstalled()) {
            return new DoctorCheckResult(self::BRIDGE_CHECK, DoctorCheckStatus::Failure, 'Not installed — run "init --provider=<platform>" to download it.');
        }

        return $this->staleBridgeTreeCheck($bridgeTree) ?? $this->bootCheck($configurationResolves);
    }

    /**
     * Runs whether or not the configuration resolves: the binary never loads a
     * stale tree.
     */
    private function staleBridgeTreeCheck(BridgeTree $bridgeTree): ?DoctorCheckResult
    {
        try {
            $bridgeTree->assertLoadable($this->standaloneConfigLoader->configuredProvider());
        } catch (StaleBridgeTreeException $staleBridgeTreeException) {
            return new DoctorCheckResult(self::BRIDGE_CHECK, DoctorCheckStatus::Failure, $this->bootFailureDetail($staleBridgeTreeException->getMessage()));
        }

        return null;
    }

    private function bootCheck(bool $configurationResolves): DoctorCheckResult
    {
        if (!$configurationResolves) {
            return new DoctorCheckResult(self::BRIDGE_CHECK, DoctorCheckStatus::Ok, 'Installed.');
        }

        $failureReason = $this->auditPreflight->failureReason();

        return null === $failureReason
            ? new DoctorCheckResult(self::BRIDGE_CHECK, DoctorCheckStatus::Ok, 'Installed and the audit boots with it.')
            : new DoctorCheckResult(self::BRIDGE_CHECK, DoctorCheckStatus::Failure, $this->bootFailureDetail($failureReason));
    }

    /**
     * Reads the reason as bytes: it may hold invalid UTF-8, on which `u()`
     * throws.
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
        $composerProbe = $this->composerAvailabilityChecker->probe();

        return $composerProbe->isAvailable
            ? new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.')
            : new DoctorCheckResult('Composer', DoctorCheckStatus::Warning, \sprintf('Not usable (%s) — the lookup_advisory tool then audits without advisory data; "init" does not need it.', OutputFormatter::escape($composerProbe->failure)));
    }

    /**
     * Names the catalog file in use, the refreshed one once `self-update` has
     * written it.
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
     * Gives a refreshed catalog no package version, which describes only the
     * packaged one.
     */
    private function pricingCatalogDetail(string $catalogPath): string
    {
        if ($catalogPath !== $this->modelsDevPricingProvider->packagedCatalogPath()) {
            return \sprintf('refreshed catalog (%s); bundled %s unused.', $catalogPath, $this->pricingCatalogPackage);
        }

        return \sprintf('%s %s (%s).', $this->pricingCatalogPackage, (new ReportPackage($this->pricingCatalogPackage))->version(), $catalogPath);
    }
}
