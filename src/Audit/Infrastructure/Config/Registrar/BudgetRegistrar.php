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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar;

use Override;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuditBudget;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class BudgetRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $maxTokens = $bundleConfiguration->budget->maxTokens;
        $maxCostUsd = $bundleConfiguration->budget->maxCostUsd;
        [$auditBudgetFactory, $auditBudgetArgs] = match (true) {
            null === $maxTokens && null === $maxCostUsd => [[AuditBudget::class, 'unlimited'], []],
            null !== $maxTokens && null !== $maxCostUsd => [[AuditBudget::class, 'forBoth'], [$maxTokens, $maxCostUsd]],
            null !== $maxTokens => [[AuditBudget::class, 'forTokens'], [$maxTokens]],
            default => [[AuditBudget::class, 'forCost'], [$maxCostUsd]],
        };

        $servicesConfigurator->set(AuditBudget::class)
            ->private()
            ->factory($auditBudgetFactory)
            ->args($auditBudgetArgs);
    }
}
