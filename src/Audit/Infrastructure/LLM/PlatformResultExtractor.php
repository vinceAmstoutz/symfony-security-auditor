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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\TokenUsage\TokenUsageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;

/**
 * Extracts token usage, tool calls, and text from symfony/ai platform
 * results, recording usage on the optional telemetry recorder.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformResultExtractor
{
    public function __construct(
        private ?TokenUsageRecorder $tokenUsageRecorder,
    ) {}

    /** @return array{0: int, 1: int, 2: int, 3: int}
     *
     * @throws NegativeTokenCountException
     */
    public function extractTokens(DeferredResult $deferredResult): array
    {
        $metadata = $deferredResult->getMetadata()->all();
        $tokenUsage = $metadata['token_usage'] ?? null;
        if (!$tokenUsage instanceof TokenUsageInterface) {
            return [0, 0, 0, 0];
        }

        $inputTokens = $tokenUsage->getPromptTokens() ?? 0;
        $outputTokens = $tokenUsage->getCompletionTokens() ?? 0;
        $cacheReadTokens = $tokenUsage->getCacheReadTokens() ?? 0;
        $cacheCreationTokens = $tokenUsage->getCacheCreationTokens() ?? 0;
        $this->tokenUsageRecorder?->record($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens);

        return [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens];
    }

    /**
     * @return list<ToolCall>
     */
    public function extractToolCalls(ResultInterface $result): array
    {
        if ($result instanceof ToolCallResult) {
            return array_values($result->getContent());
        }

        if ($result instanceof MultiPartResult) {
            foreach ($result->getContent() as $part) {
                if ($part instanceof ToolCallResult) {
                    return array_values($part->getContent());
                }
            }
        }

        return [];
    }

    public function extractText(ResultInterface $result): string
    {
        if ($result instanceof TextResult) {
            return $result->getContent();
        }

        if ($result instanceof MultiPartResult) {
            return $result->asText();
        }

        return '';
    }
}
