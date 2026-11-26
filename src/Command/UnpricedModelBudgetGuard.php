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
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class UnpricedModelBudgetGuard implements UnpricedModelBudgetGuardInterface
{
    /** @param list<string> $models */
    public function __construct(
        private PricingProviderInterface $pricingProvider,
        private array $models,
        private ?float $maxCostUsd = null,
        private ?string $cliAgent = null,
    ) {}

    /**
     * @throws void
     */
    #[Override]
    public function permitsRun(InputInterface $input, SymfonyStyle $symfonyStyle): bool
    {
        $unpricedModels = $this->unpricedModels();
        if ([] === $unpricedModels) {
            return true;
        }

        $errorStyle = $symfonyStyle->getErrorStyle();
        $errorStyle->warning(UnpricedModelNotice::forRun($unpricedModels, $this->cliAgent));

        if (null === $this->maxCostUsd) {
            return true;
        }

        $errorStyle->warning(\sprintf(
            'A cost budget (audit.budget.max_cost_usd = %s) is set but cannot be enforced for the unpriced model(s) above — real spend may exceed it.',
            $this->maxCostUsd,
        ));

        if ($input->isInteractive()) {
            return $errorStyle->confirm('Continue anyway, knowing the cost budget will not be enforced?', false);
        }

        $errorStyle->error(UnpricedModelNotice::forBudgetRefusal($this->cliAgent));

        return false;
    }

    /**
     * @throws void
     */
    #[Override]
    public function assertUnattendedRunPermitted(LoggerInterface $logger): void
    {
        $unpricedModels = $this->unpricedModels();
        if (null === $this->maxCostUsd || [] === $unpricedModels) {
            return;
        }

        $logger->warning(
            \sprintf(
                'The cost budget audit.budget.max_cost_usd = %s cannot be enforced for the unpriced model(s) %s: the audit runs, and its real spend may exceed it.',
                $this->maxCostUsd,
                implode(', ', $unpricedModels),
            ),
            ['models' => $unpricedModels, 'max_cost_usd' => $this->maxCostUsd],
        );
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
