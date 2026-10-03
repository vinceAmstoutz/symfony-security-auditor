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
 * Test fake: reads the `usage` of an OpenAI-compatible raw answer the way the
 * generic bridge's extractor does, so a test can tell the usage a provider
 * reported from the estimate a failed call would otherwise be booked at.
 */
final readonly class RawUsageExtractor implements TokenUsageExtractorInterface
{
    #[Override]
    public function extract(RawResultInterface $rawResult, array $options = []): ?TokenUsage
    {
        $usage = $rawResult->getData()['usage'] ?? null;
        if (!\is_array($usage)) {
            return null;
        }

        $promptTokens = $usage['prompt_tokens'] ?? null;
        $completionTokens = $usage['completion_tokens'] ?? null;

        return new TokenUsage(
            promptTokens: \is_int($promptTokens) ? $promptTokens : null,
            completionTokens: \is_int($completionTokens) ? $completionTokens : null,
        );
    }
}
