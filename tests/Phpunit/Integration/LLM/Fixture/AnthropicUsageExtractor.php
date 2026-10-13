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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use Symfony\AI\Platform\Result\RawResultInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;

/**
 * Test fake: reads the `usage` of an Anthropic Messages answer the way the
 * Anthropic bridge's extractor does, which counts every cache write alike
 * whatever the time the provider keeps it for.
 */
final readonly class AnthropicUsageExtractor implements TokenUsageExtractorInterface
{
    #[Override]
    public function extract(RawResultInterface $rawResult, array $options = []): ?TokenUsage
    {
        $usage = $rawResult->getData()['usage'] ?? null;
        if (!\is_array($usage)) {
            return null;
        }

        $cacheCreationTokens = $this->count($usage, 'cache_creation_input_tokens');
        $cacheReadTokens = $this->count($usage, 'cache_read_input_tokens');

        return new TokenUsage(
            promptTokens: $this->count($usage, 'input_tokens'),
            completionTokens: $this->count($usage, 'output_tokens'),
            cachedTokens: $cacheCreationTokens + $cacheReadTokens,
            cacheCreationTokens: $cacheCreationTokens,
            cacheReadTokens: $cacheReadTokens,
        );
    }

    /**
     * @param array<array-key, mixed> $usage
     */
    private function count(array $usage, string $key): int
    {
        $count = $usage[$key] ?? 0;

        return \is_int($count) ? $count : 0;
    }
}
