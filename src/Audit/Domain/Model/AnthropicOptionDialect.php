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
 * Matching is on anchored identifier prefixes, covering the Anthropic API and
 * Vertex (`claude-…`) plus Bedrock's plain and cross-region-inference ids
 * (`anthropic.claude-…`, `us.anthropic.claude-…`). An unrelated model whose
 * name merely contains "claude" is therefore not mistaken for one, and an
 * opaque gateway alias that hides its Anthropic origin reports honestly that
 * the dialect cannot be confirmed — `ConfigurationNotices` surfaces that as a
 * pre-flight notice instead of dropping the cap in silence.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AnthropicOptionDialect
{
    /** @var list<string> */
    private const array MODEL_ID_PREFIXES = [
        'claude-',
        'claude.',
        'anthropic.',
        'us.anthropic.',
        'eu.anthropic.',
        'apac.anthropic.',
    ];

    public static function honoredBy(string $model): bool
    {
        foreach (self::MODEL_ID_PREFIXES as $modelIdPrefix) {
            if (str_starts_with($model, $modelIdPrefix)) {
                return true;
            }
        }

        return false;
    }
}
