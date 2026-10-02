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
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnconvertedAnswerException;

/**
 * Reads the raw answer of a call its bridge failed to convert again, for what
 * the bridge's exception no longer says. Azure, and the gateways relaying it,
 * refuse a prompt the content filter caught with an HTTP 400 whose
 * `error.code` is `content_filter`; the bridges keep only its message. A tool
 * call the output token limit cut off mid-way through its arguments fails as
 * a malformed tool call, while the answer's finish reason — `length` in Chat
 * Completions, `incomplete_details.reason: max_output_tokens` in the Responses
 * API — says it was cut off, so asking again would hit the same limit. Only
 * the failure to convert that very answer is read against it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConversionFailureExplainer
{
    private const string CONTENT_FILTER_ERROR_CODE = 'content_filter';

    private const string OUTPUT_LIMIT_FINISH_REASON = 'length';

    private const string OUTPUT_LIMIT_INCOMPLETE_REASON = 'max_output_tokens';

    public function explain(Throwable $throwable, ?DeferredResult $deferredResult): Throwable
    {
        if (!$deferredResult instanceof DeferredResult || !$this->isConversionFailure($throwable, $deferredResult)) {
            return $throwable;
        }

        $stopReason = $this->stopReasonOf($this->rawAnswer($deferredResult));

        return null === $stopReason ? $throwable : UnconvertedAnswerException::cutShort($throwable, $stopReason);
    }

    private function isConversionFailure(Throwable $throwable, DeferredResult $deferredResult): bool
    {
        try {
            $deferredResult->getResult();
        } catch (Throwable $conversionFailure) {
            return $conversionFailure === $throwable;
        }

        return false;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function rawAnswer(DeferredResult $deferredResult): array
    {
        try {
            return $deferredResult->getRawResult()->getData();
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * @param array<array-key, mixed> $rawAnswer
     */
    private function stopReasonOf(array $rawAnswer): ?string
    {
        return match (true) {
            self::CONTENT_FILTER_ERROR_CODE === $this->field($rawAnswer['error'] ?? null, 'code') => 'content-filter',
            self::OUTPUT_LIMIT_INCOMPLETE_REASON === $this->field($rawAnswer['incomplete_details'] ?? null, 'reason'),
            $this->anyChoiceFinishedFor(self::OUTPUT_LIMIT_FINISH_REASON, $rawAnswer['choices'] ?? null) => 'length',
            default => null,
        };
    }

    private function anyChoiceFinishedFor(string $finishReason, mixed $choices): bool
    {
        if (!\is_array($choices)) {
            return false;
        }

        foreach ($choices as $choice) {
            if ($finishReason === $this->field($choice, 'finish_reason')) {
                return true;
            }
        }

        return false;
    }

    private function field(mixed $object, string $key): mixed
    {
        return \is_array($object) ? $object[$key] ?? null : null;
    }
}
