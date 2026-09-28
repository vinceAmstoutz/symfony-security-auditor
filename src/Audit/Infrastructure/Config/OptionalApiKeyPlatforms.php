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
 * The `symfony/ai` platforms whose `api_key` node is not `->isRequired()`, as
 * listed by `symfony/ai-bundle`'s `config/platform/*.php`. Only these can be
 * written without a credential: every other platform fails container
 * validation the moment the key is missing, so `--no-api-key` is refused for
 * them rather than producing a file the next run cannot build.
 *
 * Optional is not the same as unnecessary. A gateway behind `generic` still
 * wants its token, which is why the key is omitted only when asked for, never
 * by default.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class OptionalApiKeyPlatforms
{
    /**
     * @var list<string>
     */
    public const array NAMES = ['deepgram', 'elevenlabs', 'generic', 'ollama', 'openresponses', 'vertexai'];

    public static function accept(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::NAMES, true);
    }
}
