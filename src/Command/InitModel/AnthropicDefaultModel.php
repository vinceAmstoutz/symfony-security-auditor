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

/**
 * Claude Opus 5.5, offered as the default for Anthropic when the price
 * catalog lists none of its models.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AnthropicDefaultModel implements ModelSourceInterface
{
    public const string MODEL = 'claude-opus-5-5';

    #[Override]
    public function offer(ProviderKey $providerKey, ?string $endpoint): ?ModelOfferInterface
    {
        return 'anthropic' === $providerKey->platform ? new TypedModelOffer('Which model should the <options=bold>auditor</> use?', self::MODEL) : null;
    }
}
