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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatformFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionCliInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionClis;

/**
 * The models a Claude or ChatGPT subscription runs, the first one suggested
 * for the auditor and the lightest one to review the findings.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SubscriptionModels implements ModelSourceInterface
{
    #[Override]
    public function offer(ProviderKey $providerKey, ?string $endpoint): ?ModelOfferInterface
    {
        $models = CliAgentPlatformFactory::SUBSCRIPTION_MODELS[$providerKey->platform] ?? null;

        return null === $models ? null : NumberedModelOffer::of('Which model should the <options=bold>auditor</> use? Pick a number, or type a model id', $models, $models[0]);
    }

    public function reviewerOffer(ProviderKey $providerKey): ?ModelOfferInterface
    {
        $models = CliAgentPlatformFactory::SUBSCRIPTION_MODELS[$providerKey->platform] ?? null;
        $subscriptionCli = SubscriptionClis::bundled()->of($providerKey->platform);

        return null === $models || !$subscriptionCli instanceof SubscriptionCliInterface
            ? null
            : NumberedModelOffer::of('Which model should <options=bold>review the findings</>? Pick a number, or type a model id', $models, $subscriptionCli->suggestedReviewerModel());
    }
}
