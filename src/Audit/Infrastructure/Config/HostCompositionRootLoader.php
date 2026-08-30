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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use JsonException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditExecutionConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;

/**
 * Runs {@see CoreCompositionRoot} against a plain `ContainerBuilder`, so a host
 * that is not a Symfony bundle wires the audit graph from the same source the
 * bundle extension uses instead of instantiating the bundle to reach it.
 *
 * Symfony's `ExtensionTrait` additionally sets the loader's current directory
 * and registers aliases for singly-implemented interfaces. Neither is done here:
 * the composition root imports by absolute path, and `config/services.php`
 * declares its aliases explicitly, so both are provably no-ops for this graph.
 *
 * @phpstan-import-type BundleConfigArray from BundleConfiguration
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class HostCompositionRootLoader
{
    public function __construct(
        private CoreCompositionRoot $coreCompositionRoot,
        private AuditConfigurationProcessor $auditConfigurationProcessor = new AuditConfigurationProcessor(),
    ) {}

    /**
     * @param array<array-key, mixed> $auditConfig
     *
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    public function load(array $auditConfig, ContainerBuilder $containerBuilder, string $environment): void
    {
        $compositionRootLoader = new CompositionRootLoader($containerBuilder, new FileLocator(), $environment);

        /** @var BundleConfigArray $processedConfig */
        $processedConfig = $this->auditConfigurationProcessor->process($auditConfig);

        $this->coreCompositionRoot->register(
            $compositionRootLoader->containerConfigurator(__FILE__),
            $containerBuilder,
            BundleConfiguration::fromArray($processedConfig),
        );
    }
}
