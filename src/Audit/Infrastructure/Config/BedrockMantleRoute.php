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

use function Symfony\Component\String\u;

/**
 * The Bedrock Mantle route `init` writes for a model. Mantle takes an API key
 * where the default InvokeModel route needs an AWS SDK client service, and it
 * serves each vendor on its own protocol: Anthropic models on the Messages
 * API, Gemma on Responses, every other open-weight model on Chat Completions,
 * as the `symfony/ai-bedrock-platform` Mantle model catalogs list them. A model
 * is named after its vendor there (`anthropic.claude-opus-4-8`), which is what
 * the route is read from.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BedrockMantleRoute
{
    private const string PLATFORM = 'bedrock';

    private const string VENDOR_PREFIX = '/^[a-z]+\./';

    /**
     * The bridge each non-Anthropic route borrows its protocol from, which the
     * Bedrock bridge only suggests: without it the configuration does not build.
     */
    private const array COMPANION_PLATFORMS = ['completions' => 'generic', 'responses' => 'openresponses'];

    public static function applies(ProviderKey $providerKey): bool
    {
        return self::PLATFORM === $providerKey->platform;
    }

    public static function namesAVendor(string $model): bool
    {
        return 1 === preg_match(self::VENDOR_PREFIX, $model);
    }

    public static function companionPlatform(string $model): ?string
    {
        return self::COMPANION_PLATFORMS[self::of($model)] ?? null;
    }

    public static function of(string $model): string
    {
        return match (true) {
            u($model)->startsWith('anthropic.') => 'messages',
            u($model)->startsWith('google.') => 'responses',
            default => 'completions',
        };
    }
}
