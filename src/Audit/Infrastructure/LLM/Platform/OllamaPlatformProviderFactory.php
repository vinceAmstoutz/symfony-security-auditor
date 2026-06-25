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

use Symfony\AI\Platform\Bridge\Ollama\Factory;
use Symfony\AI\Platform\PlatformInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class OllamaPlatformProviderFactory implements PlatformProviderFactoryInterface
{
    private const string PROVIDER = 'ollama';

    public function provider(): string
    {
        return self::PROVIDER;
    }

    public function create(PlatformConnection $platformConnection): PlatformInterface
    {
        return Factory::createPlatform($platformConnection->endpoint, $platformConnection->apiKey);
    }
}
