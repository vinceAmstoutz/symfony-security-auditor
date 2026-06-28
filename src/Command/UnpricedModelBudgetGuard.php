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
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class UnpricedModelBudgetGuard implements UnpricedModelBudgetGuardInterface
{
    /** @param list<string> $models */
    public function __construct(
        private PricingProviderInterface $pricingProvider,
        private array $models,
        private ?float $maxCostUsd = null,
    ) {}

    #[Override]
    public function permitsRun(InputInterface $input, SymfonyStyle $symfonyStyle): bool
    {
        $unpricedModels = $this->unpricedModels();
        if ([] === $unpricedModels) {
            return true;
        }

        $errorStyle = $symfonyStyle->getErrorStyle();
        $errorStyle->warning(\sprintf(
            'No published pricing for the configured model(s): %s. Cost reporting will show $0.00 for these — correct for local or self-hosted models (e.g. Ollama, LM Studio); otherwise the name is likely a typo or an unlisted model.',
            implode(', ', $unpricedModels),
        ));

        if (null === $this->maxCostUsd) {
            return true;
        }

        $errorStyle->warning(\sprintf(
            'A cost budget (audit.budget.max_cost_usd = %s) is set but cannot be enforced for the unpriced model(s) above — real spend may exceed it.',
            $this->maxCostUsd,
        ));

        if ($input->isInteractive()) {
            return $symfonyStyle->confirm('Continue anyway, knowing the cost budget will not be enforced?', false);
        }

        $errorStyle->error('Refusing to start a budgeted audit with an unpriceable model in non-interactive mode. Configure a model with published pricing, or remove audit.budget.max_cost_usd.');

        return false;
    }

    /** @return list<string> */
    private function unpricedModels(): array
    {
        $unpricedModels = [];
        foreach ($this->models as $model) {
            if ('' !== $model && !$this->pricingProvider->hasModel($model)) {
                $unpricedModels[$model] = $model;
            }
        }

        return array_values($unpricedModels);
    }
}
