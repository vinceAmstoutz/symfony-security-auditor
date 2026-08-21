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
 * per request. Gemini and the OpenAI Responses bridge reject those keys
 * outright, so sending them would fail the call rather than cap it.
 *
 * Matching is anchored, never a substring. A bare id must start with `claude-`
 * or `claude.` (the Anthropic API and Vertex). A vendor-qualified id must carry
 * an `anthropic` dot-segment followed by a `claude…` one, which covers Bedrock's
 * plain `anthropic.claude-…` and every cross-region-inference prefix it has or
 * gains (`us.`, `eu.`, `au.`, `jp.`, `global.`, …) without enumerating them —
 * the shipped `symfony/models-dev` catalog prices all of those. The `?options`
 * query string `symfony/ai-bundle` supports is stripped first, then a
 * provider-qualified id is matched on its final `/` segment, so the gateway
 * forms that name the model outright (`anthropic/claude-…`,
 * `publishers/anthropic/models/claude-…`) are recognized too, and an option
 * value containing a `/` cannot hide the model.
 * An unrelated model whose name merely contains "claude" is therefore not
 * mistaken for one, while an opaque gateway alias that hides its
 * Anthropic origin reports honestly that the dialect cannot be confirmed —
 * `ConfigurationNotices` surfaces that as a pre-flight notice instead of
 * dropping the cap in silence.
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
