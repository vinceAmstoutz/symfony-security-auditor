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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileTypeClassifierInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\SymfonyToolRegistryFactory;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyToolRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(SymfonyToolRegistryFactory::class)
            ->args([service('logger'), service(AdvisoryDatabaseInterface::class), service(ProjectFileTypeClassifierInterface::class)]);
        $servicesConfigurator->alias(ToolRegistryFactoryInterface::class, SymfonyToolRegistryFactory::class);
    }
}
