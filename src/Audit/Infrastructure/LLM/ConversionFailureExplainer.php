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
 * `error.code` is `content_filter`; the bridges keep only its message. Only
 * the failure to convert that very answer is read against it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConversionFailureExplainer
{
    private const string CONTENT_FILTER_ERROR_CODE = 'content_filter';

    public function explain(Throwable $throwable, ?DeferredResult $deferredResult): Throwable
    {
        if (!$deferredResult instanceof DeferredResult || !$this->isConversionFailure($throwable, $deferredResult)) {
            return $throwable;
        }

        if (self::CONTENT_FILTER_ERROR_CODE === $this->errorCode($this->rawAnswer($deferredResult))) {
            return UnconvertedAnswerException::cutShort($throwable, 'content-filter');
        }

        return $throwable;
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
    private function errorCode(array $rawAnswer): mixed
    {
        $error = $rawAnswer['error'] ?? null;

        return \is_array($error) ? $error['code'] ?? null : null;
    }
}
