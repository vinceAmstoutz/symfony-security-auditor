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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\UnpricedCostCapWarning;

final class UnpricedCostCapWarnings
{
    public static function of(AuditBudget $auditBudget, LoggerInterface $logger): UnpricedCostCapWarning
    {
        $oneModelPricingProvider = new OneModelPricingProvider();

        return new UnpricedCostCapWarning($auditBudget, new CostCalculator($oneModelPricingProvider), $oneModelPricingProvider, $logger);
    }

    public static function messageFor(string $model): string
    {
        return \sprintf('audit.budget.max_cost_usd cannot be enforced for model "%s": it has no price, so its calls count as $0; audit.budget.max_tokens still applies.', $model);
    }
}
