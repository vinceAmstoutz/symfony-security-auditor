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

use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModelListInterface;

/**
 * Asks `init` which model to write, the way the chosen provider calls for:
 * none for a subscription, a pulled model for Ollama, a priced list where
 * the catalog has one, the model id otherwise.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class InitModelQuestion
{
    private const string DEFAULT_MODEL = 'claude-opus-5-5';

    private const string DEFAULT_MODEL_ID = '#(?:^|[./])claude-opus-5-5$#';

    public function __construct(
        private ?PricedModelListInterface $pricedModelList,
    ) {}

    public function ask(SymfonyStyle $symfonyStyle, ProviderKey $providerKey): string
    {
        $subscriptionModel = CliAgentPlatforms::DEFAULT_MODELS[$providerKey->platform] ?? null;
        if (null !== $subscriptionModel) {
            return $subscriptionModel;
        }

        $pricedModels = $this->pricedModelList?->pricedModels($providerKey->platform) ?? [];
        $modelIds = array_map(static fn (PricedModel $pricedModel): string => $pricedModel->id, $pricedModels);

        if ([] === $modelIds && 'ollama' === $providerKey->platform) {
            return InitPrompt::required($symfonyStyle, 'Which Ollama model should the auditor use? Type the name of a model you pulled, e.g. qwen3 or llama3.3');
        }

        if ([] === $modelIds && 'anthropic' !== $providerKey->platform) {
            return InitPrompt::required($symfonyStyle, 'Which model should the auditor use? Type its id as your provider names it');
        }

        return [] === $modelIds
            ? InitPrompt::withDefault($symfonyStyle, 'Which model should the auditor use?', self::DEFAULT_MODEL)
            : NumberedChoice::ask(
                $symfonyStyle,
                'Which model should the auditor use? Pick a number, or type any model id',
                array_map($this->modelChoice(...), $pricedModels),
                $this->defaultModel($modelIds),
                $modelIds,
            );
    }

    /**
     * @param non-empty-list<string> $modelIds the most expensive first
     */
    private function defaultModel(array $modelIds): string
    {
        foreach ($modelIds as $modelId) {
            if (1 === preg_match(self::DEFAULT_MODEL_ID, $modelId)) {
                return $modelId;
            }
        }

        return $modelIds[intdiv(\count($modelIds) - 1, 2)];
    }

    private function modelChoice(PricedModel $pricedModel): string
    {
        return null === $pricedModel->outputPrice
            ? \sprintf('%s ($%s in per million tokens)', $pricedModel->id, $pricedModel->inputPrice)
            : \sprintf('%s ($%s in, $%s out per million tokens)', $pricedModel->id, $pricedModel->inputPrice, $pricedModel->outputPrice);
    }
}
