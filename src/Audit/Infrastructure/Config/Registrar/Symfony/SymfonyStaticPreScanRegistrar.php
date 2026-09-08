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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony;

use Override;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Scan\SarifImportingPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * The regex risk markers hunt Symfony shapes — `|raw`, `csrf_protection: false`,
 * a missing `setParameter` — so the scanner belongs to the profile even though
 * the port it fills does not.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyStaticPreScanRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(RegexStaticPreScanner::class)
            ->args([param('symfony_security_auditor.scan.custom_risk_patterns'), service('logger')]);

        $staticPreScanner = $bundleConfiguration->audit->staticPreScanEnabled
            ? RegexStaticPreScanner::class
            : NullStaticPreScanner::class;

        if ([] === $bundleConfiguration->scan->importSarifPaths) {
            $servicesConfigurator->alias(StaticPreScannerInterface::class, $staticPreScanner);

            return;
        }

        $servicesConfigurator->set(SarifImportingPreScanner::class)
            ->private()
            ->args([
                service($staticPreScanner),
                $bundleConfiguration->scan->importSarifPaths,
                service(Filesystem::class),
                service(AuditedProjectPathHolder::class),
            ]);
        $servicesConfigurator->alias(StaticPreScannerInterface::class, SarifImportingPreScanner::class);
    }
}
