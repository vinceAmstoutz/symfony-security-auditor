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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ProjectFileTypeClassifierInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyProjectFileTypeClassifier;

/**
 * Teaches the auditor Symfony's file conventions.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyClassifierRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(SymfonyProjectFileTypeClassifier::class);
        $servicesConfigurator->alias(ProjectFileTypeClassifierInterface::class, SymfonyProjectFileTypeClassifier::class);
    }
}
