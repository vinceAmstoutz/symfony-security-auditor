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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

/**
 * The `symfony/ai` platforms `init --no-api-key` can write: those whose
 * `api_key` is optional in `symfony/ai-bundle`'s `config/platform/*.php`,
 * except `vertexai`, which requires it unless `location` and `project_id`
 * are set.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class OptionalApiKeyPlatforms
{
    /**
     * @var list<string>
     */
    public const array NAMES = ['bedrock', 'deepgram', 'elevenlabs', 'generic', 'ollama', 'openresponses'];

    public static function accept(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::NAMES, true);
    }
}
