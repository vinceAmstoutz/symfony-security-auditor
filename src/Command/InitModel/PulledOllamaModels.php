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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelListInterface;

/**
 * The models an Ollama server pulled, or the name of one typed when it lists
 * none.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PulledOllamaModels implements ModelSourceInterface
{
    public function __construct(
        private ?PulledModelListInterface $pulledModelList,
    ) {}

    #[Override]
    public function offer(ProviderKey $providerKey, ?string $endpoint): ?ModelOfferInterface
    {
        if ('ollama' !== $providerKey->platform) {
            return null;
        }

        $pulledModels = null === $endpoint ? [] : $this->pulledModelList?->pulledModels($endpoint) ?? [];

        return [] === $pulledModels
            ? new TypedModelOffer('Which Ollama model should the <options=bold>auditor</> use? Type the name of a model you pulled, e.g. qwen3 or llama3.3')
            : NumberedModelOffer::of('Which Ollama model should the <options=bold>auditor</> use? Pick a number, or type a model name', $pulledModels, $pulledModels[0]);
    }
}
