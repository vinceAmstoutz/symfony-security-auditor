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
 * The Bedrock Mantle route `init` writes for a model, read from its vendor
 * prefix (`anthropic.claude-opus-4-8`): Messages for Anthropic, Responses for
 * Gemma, Chat Completions for every other model.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class BedrockMantleRoute
{
    private const string PLATFORM = 'bedrock';

    private const string VENDOR_PREFIX = '/^[a-z]+\./';

    /**
     * The bridge each non-Anthropic route needs beside Bedrock's, which only
     * suggests it.
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
