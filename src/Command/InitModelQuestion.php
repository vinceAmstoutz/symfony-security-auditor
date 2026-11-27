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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\AnthropicDefaultModel;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\ModelOfferInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\ModelSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\PricedModels;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\PulledOllamaModels;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\SubscriptionModels;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\TypedModelOffer;

/**
 * Asks `init` which model to write, from the first source that offers models
 * for the chosen provider: its subscription, the models Ollama pulled, the
 * price catalog, Anthropic's default, else the model id typed.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class InitModelQuestion
{
    private SubscriptionModels $subscriptionModels;

    /**
     * @var list<ModelSourceInterface>
     */
    private array $modelSources;

    public function __construct(
        ?PricedModelListInterface $pricedModelList,
        ?PulledModelListInterface $pulledModelList,
        private bool $interactive,
    ) {
        $this->subscriptionModels = new SubscriptionModels();
        $this->modelSources = [$this->subscriptionModels, new PulledOllamaModels($pulledModelList), new PricedModels($pricedModelList), new AnthropicDefaultModel()];
    }

    /**
     * Returns null where no model can be offered without interaction.
     */
    public function ask(SymfonyStyle $symfonyStyle, ProviderKey $providerKey, ?string $endpoint = null): ?string
    {
        return ($this->offerFor($providerKey, $endpoint) ?? TypedModelOffer::anyModelId())->ask($symfonyStyle, $this->interactive);
    }

    public function askReviewer(SymfonyStyle $symfonyStyle, ProviderKey $providerKey): ?string
    {
        return $this->subscriptionModels->reviewerOffer($providerKey)?->ask($symfonyStyle, $this->interactive);
    }

    private function offerFor(ProviderKey $providerKey, ?string $endpoint): ?ModelOfferInterface
    {
        foreach ($this->modelSources as $modelSource) {
            $modelOffer = $modelSource->offer($providerKey, $endpoint);
            if ($modelOffer instanceof ModelOfferInterface) {
                return $modelOffer;
            }
        }

        return null;
    }
}
