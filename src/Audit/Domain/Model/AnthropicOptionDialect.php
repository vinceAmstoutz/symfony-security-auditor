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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * Whether a model identifier belongs to the Anthropic option dialect — the one
 * `symfony/ai` bridge family that accepts `max_tokens` and `response_format`
 * per request. Other bridges reject those keys, failing the call rather than
 * capping it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AnthropicOptionDialect
{
    /** @var list<string> */
    private const array BARE_MODEL_ID_PREFIXES = [
        'claude-',
        'claude.',
    ];

    private const string VENDOR_SEGMENT = 'anthropic';

    private const string FAMILY_SEGMENT_PREFIX = 'claude';

    public static function honoredBy(string $model): bool
    {
        $modelId = self::withoutGatewayPrefix(self::withoutOptionsQueryString($model));

        return self::isBareClaudeId($modelId) || self::isVendorQualifiedClaudeId($modelId);
    }

    private static function isBareClaudeId(string $modelId): bool
    {
        foreach (self::BARE_MODEL_ID_PREFIXES as $modelIdPrefix) {
            if (str_starts_with($modelId, $modelIdPrefix)) {
                return true;
            }
        }

        return false;
    }

    private static function isVendorQualifiedClaudeId(string $modelId): bool
    {
        $segments = explode('.', $modelId);

        foreach ($segments as $position => $segment) {
            if (self::VENDOR_SEGMENT === $segment && str_starts_with($segments[$position + 1] ?? '', self::FAMILY_SEGMENT_PREFIX)) {
                return true;
            }
        }

        return false;
    }

    private static function withoutOptionsQueryString(string $model): string
    {
        $withoutOptions = strstr($model, '?', true);

        return false === $withoutOptions ? $model : $withoutOptions;
    }

    private static function withoutGatewayPrefix(string $model): string
    {
        $lastSeparatorPosition = strrpos($model, '/');

        return false === $lastSeparatorPosition ? $model : substr($model, $lastSeparatorPosition + 1);
    }
}
