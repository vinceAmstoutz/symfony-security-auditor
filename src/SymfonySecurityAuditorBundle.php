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

namespace VinceAmstoutz\SymfonySecurityAuditor;

use JsonException;
use Override;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidAuditExecutionConfigurationException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CoreCompositionRoot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\SymfonyProfile;

/**
 * @phpstan-import-type BundleConfigArray from BundleConfiguration
 */
final class SymfonySecurityAuditorBundle extends AbstractBundle
{
    #[Override]
    public function configure(DefinitionConfigurator $definition): void
    {
        (new AuditConfigurationDefinition())
            ->defineChildren($definition->rootNode()->children());
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    #[Override]
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        /** @var BundleConfigArray $config */
        $bundleConfiguration = BundleConfiguration::fromArray($config);

        (new CoreCompositionRoot(new SymfonyProfile()))->register($container, $builder, $bundleConfiguration);
    }
}
