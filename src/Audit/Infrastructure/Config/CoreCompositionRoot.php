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
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\BudgetRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\CustomSkillRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\EscalationRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ImplementationAliasRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\LlmClientRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\RateLimiterRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;

/**
 * The single description of the audit object graph. The bundle extension, the
 * standalone binary and any other host call this; a host adds only its own
 * framework-integration services on top.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CoreCompositionRoot
{
    /**
     * @var list<ServiceRegistrarInterface>
     */
    private array $serviceRegistrars;

    /**
     * @param list<ServiceRegistrarInterface> $profileRegistrars the host's framework profile — the
     *                                                           attacker skills and source parsers
     *                                                           that only make sense for the
     *                                                           framework being audited
     */
    public function __construct(array $profileRegistrars = [])
    {
        $this->serviceRegistrars = [...$this->coreRegistrars(), ...$profileRegistrars];
    }

    /**
     * @throws JsonException
     */
    public function register(ContainerConfigurator $containerConfigurator, ContainerBuilder $containerBuilder, BundleConfiguration $bundleConfiguration): void
    {
        $containerConfigurator->import(\sprintf('%s/../../../../config/services.php', __DIR__));

        (new ContainerParameterRegistrar())->register($bundleConfiguration, $containerBuilder);

        $servicesConfigurator = $containerConfigurator->services();
        foreach ($this->serviceRegistrars as $serviceRegistrar) {
            $serviceRegistrar->register($servicesConfigurator, $bundleConfiguration);
        }
    }

    /**
     * @return list<ServiceRegistrarInterface>
     */
    private function coreRegistrars(): array
    {
        return [
            new BudgetRegistrar(),
            new RateLimiterRegistrar(),
            new LlmClientRegistrar(),
            new ImplementationAliasRegistrar(),
            new CustomSkillRegistrar(),
            new EscalationRegistrar(),
        ];
    }
}
