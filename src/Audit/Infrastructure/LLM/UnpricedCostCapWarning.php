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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

/**
 * Warns once per model that `audit.budget.max_cost_usd` cannot stop a run
 * whose client answers under a model the pricing catalog has no price for:
 * its calls count as $0, while `audit.budget.max_tokens` still applies.
 * Mutable by design — opted out of the final readonly rule as a per-run
 * accumulator (see .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class UnpricedCostCapWarning
{
    /** @var array<string, true> */
    private array $warnedModels = [];

    public function __construct(
        private readonly AuditBudget $auditBudget,
        private readonly CostCalculator $costCalculator,
        private readonly PricingProviderInterface $pricingProvider,
        private readonly LoggerInterface $logger,
    ) {}

    public function check(LLMResponse $llmResponse): void
    {
        if (null === $this->auditBudget->maxCostUsd()) {
            return;
        }

        $billedModel = $this->costCalculator->billedModel($llmResponse->model(), $llmResponse->reportedModel());
        if ($this->pricingProvider->hasModel($billedModel) || \array_key_exists($billedModel, $this->warnedModels)) {
            return;
        }

        $this->warnedModels[$billedModel] = true;
        $this->logger->warning(\sprintf('audit.budget.max_cost_usd cannot be enforced for model "%s": it has no price, so its calls count as $0; audit.budget.max_tokens still applies.', $billedModel));
    }
}
