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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform;

use Symfony\AI\Platform\Bridge\Anthropic\Factory;
use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\Exception\MissingPlatformApiKeyException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AnthropicPlatformProviderFactory implements PlatformProviderFactoryInterface
{
    private const string PROVIDER = 'anthropic';

    public function provider(): string
    {
        return self::PROVIDER;
    }

    public function create(PlatformConnection $platformConnection): PlatformInterface
    {
        if (null === $platformConnection->apiKey) {
            throw MissingPlatformApiKeyException::forProvider(self::PROVIDER);
        }

        return Factory::createPlatform($platformConnection->apiKey);
    }
}
