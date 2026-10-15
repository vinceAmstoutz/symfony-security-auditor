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

use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\FinishReason\FinishReasonCase;

use function Symfony\Component\String\u;

/**
 * Reads why the provider stopped an answer, warning when the answer it reads
 * may have lost findings.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FinishReasonReader
{
    private const string EMPTY_CONTENT_STOP_REASON = 'empty_content';

    /** @var list<string> */
    private const array ABNORMAL_GEMINI_FINISH_REASONS = [
        'MALFORMED_FUNCTION_CALL',
        'UNEXPECTED_TOOL_CALL',
        'TOO_MANY_TOOL_CALLS',
        'MISSING_THOUGHT_SIGNATURE',
        'RECITATION',
        'LANGUAGE',
        'OTHER',
        'FINISH_REASON_UNSPECIFIED',
        'IMAGE_PROHIBITED_CONTENT',
        'IMAGE_RECITATION',
        'IMAGE_OTHER',
        'NO_IMAGE',
        'MODEL_ARMOR',
    ];

    public function __construct(private LoggerInterface $logger) {}

    /**
     * `$text` is the text of the answer that ended on `$finishReason`.
     */
    public function stopReason(FinishReason $finishReason, string $text): string
    {
        if ($this->endedAbnormallyWithNothingInIt($finishReason, $text)) {
            $this->logger->warning('LLM response ended abnormally with no content — it is no verdict on the prompt and is answered as empty_content', ['finish_reason' => $finishReason->getRaw()]);

            return self::EMPTY_CONTENT_STOP_REASON;
        }

        $this->warnWhenDegraded($finishReason);

        return $this->normalizedStopReason($finishReason);
    }

    /**
     * Gemini and Vertex AI end an answer the model did not finish with one of
     * `ABNORMAL_GEMINI_FINISH_REASONS`, which their bridges map to no
     * normalized case and hand back as an empty text: with no text in it, it
     * is nothing the model said. Any other word is read as the provider's own.
     */
    private function endedAbnormallyWithNothingInIt(FinishReason $finishReason, string $text): bool
    {
        return \in_array(u($finishReason->getRaw())->upper()->toString(), self::ABNORMAL_GEMINI_FINISH_REASONS, true)
            && '' === trim($text);
    }

    /**
     * Truncation and content filtering come back as symfony/ai's case values
     * whatever the provider calls them (`max_tokens`, `MAX_TOKENS`, `length`,
     * …), so `LLMResponse::isDegraded()` recognizes them; every other reason
     * keeps the provider's own word.
     */
    private function normalizedStopReason(FinishReason $finishReason): string
    {
        return $finishReason->is(FinishReasonCase::LENGTH, FinishReasonCase::CONTENT_FILTER)
            ? $finishReason->getCase()->value
            : $finishReason->getRaw();
    }

    private function warnWhenDegraded(FinishReason $finishReason): void
    {
        $warning = match (true) {
            $finishReason->is(FinishReasonCase::LENGTH) => 'LLM response was truncated by the output token limit — findings may be lost; raise max_output_tokens (or the per-agent attacker/reviewer variants)',
            $finishReason->is(FinishReasonCase::CONTENT_FILTER) => 'LLM response was suppressed by the provider content filter — findings may be lost',
            default => null,
        };

        if (null !== $warning) {
            $this->logger->warning($warning, ['finish_reason' => $finishReason->getRaw()]);
        }
    }
}
