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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModelListInterface;

/**
 * The newest paid model of each family the price catalog lists for the
 * provider, with its price. Claude Opus 5.5 is suggested where listed, else
 * the model in the middle of the price range.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PricedModels implements ModelSourceInterface
{
    private const string SUGGESTED_MODEL_ID = '#(?:^|[./])claude-opus-5-5(?:@[a-z0-9-]+)?$#';

    public function __construct(
        private ?PricedModelListInterface $pricedModelList,
    ) {}

    #[Override]
    public function offer(ProviderKey $providerKey, ?string $endpoint): ?ModelOfferInterface
    {
        $pricedModels = $this->pricedModelList?->pricedModels($providerKey->platform) ?? [];
        if ([] === $pricedModels) {
            return null;
        }

        $modelIds = array_map(static fn (PricedModel $pricedModel): string => $pricedModel->id, $pricedModels);

        return new NumberedModelOffer(
            'Which model should the <options=bold>auditor</> use? Pick a number, or type any model id',
            array_map($this->label(...), $pricedModels),
            $modelIds,
            $this->suggested($modelIds),
            preamble: 'Prices are per million tokens; "audit --dry-run <path>" estimates what an audit of your project would cost.',
        );
    }

    /**
     * @param non-empty-list<string> $modelIds the most expensive first
     */
    private function suggested(array $modelIds): string
    {
        foreach ($modelIds as $modelId) {
            if (1 === preg_match(self::SUGGESTED_MODEL_ID, $modelId)) {
                return $modelId;
            }
        }

        return $modelIds[intdiv(\count($modelIds) - 1, 2)];
    }

    private function label(PricedModel $pricedModel): string
    {
        return null === $pricedModel->outputPrice
            ? \sprintf('%s ($%s in per million tokens)', $pricedModel->id, $pricedModel->inputPrice)
            : \sprintf('%s ($%s in, $%s out per million tokens)', $pricedModel->id, $pricedModel->inputPrice, $pricedModel->outputPrice);
    }
}
