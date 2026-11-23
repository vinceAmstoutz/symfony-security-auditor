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
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnconvertedAnswerException;

/**
 * Reads the raw answer of a call its bridge failed to convert for what the
 * bridge's exception lost: Azure's HTTP 400 `content_filter`, a tool call the
 * output limit cut off, or an HTTP 413, read as too large. A 408, 425, 429 or
 * 5xx is wrapped as transient whatever the bridge made of its body; any other
 * HTTP 4xx is wrapped as a refusal that books nothing yet is classified by
 * the bridge's message. Returns any other failure unchanged, a failure that
 * is not the conversion of that very answer included.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConversionFailureExplainer
{
    private const string CONTENT_FILTER_ERROR_CODE = 'content_filter';

    private const string OUTPUT_LIMIT_FINISH_REASON = 'length';

    private const string OUTPUT_LIMIT_INCOMPLETE_REASON = 'max_output_tokens';

    private const int PAYLOAD_TOO_LARGE_STATUS = 413;

    private const int FIRST_CLIENT_ERROR_STATUS = 400;

    private const int LAST_CLIENT_ERROR_STATUS = 499;

    private const int FIRST_SERVER_ERROR_STATUS = 500;

    /** @var list<int> */
    private const array RETRIED_CLIENT_ERROR_STATUSES = [408, 425, 429];

    public function explain(Throwable $throwable, ?DeferredResult $deferredResult): Throwable
    {
        if (!$deferredResult instanceof DeferredResult || !$this->isConversionFailure($throwable, $deferredResult)) {
            return $throwable;
        }

        $status = $this->statusCode($deferredResult);
        if (self::PAYLOAD_TOO_LARGE_STATUS === $status) {
            return UnconvertedAnswerException::refusedAsTooLarge($throwable);
        }

        $explained = $this->explainedByTheRawAnswer($throwable, $deferredResult, $status);

        return $this->clearsOnItsOwn($status) ? TransientHttpStatusException::from($explained, $status) : $explained;
    }

    private function explainedByTheRawAnswer(Throwable $throwable, DeferredResult $deferredResult, ?int $status): Throwable
    {
        $stopReason = $this->stopReasonOf($this->rawAnswer($deferredResult));
        if (null !== $stopReason) {
            return UnconvertedAnswerException::cutShort($throwable, $stopReason);
        }

        return $this->isRefusal($status) ? UnconvertedAnswerException::refusedWithStatus($throwable, $status) : $throwable;
    }

    /**
     * @phpstan-assert-if-true =int $status
     */
    private function clearsOnItsOwn(?int $status): bool
    {
        return null !== $status
            && (\in_array($status, self::RETRIED_CLIENT_ERROR_STATUSES, true) || $status >= self::FIRST_SERVER_ERROR_STATUS);
    }

    /**
     * @phpstan-assert-if-true int $status
     */
    private function isRefusal(?int $status): bool
    {
        return null !== $status
            && $status >= self::FIRST_CLIENT_ERROR_STATUS
            && $status <= self::LAST_CLIENT_ERROR_STATUS
            && !\in_array($status, self::RETRIED_CLIENT_ERROR_STATUSES, true);
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

    private function statusCode(DeferredResult $deferredResult): ?int
    {
        $response = $deferredResult->getRawResult()->getObject();
        if (!$response instanceof ResponseInterface) {
            return null;
        }

        try {
            return $response->getStatusCode();
        } catch (TransportExceptionInterface) {
            return null;
        }
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
