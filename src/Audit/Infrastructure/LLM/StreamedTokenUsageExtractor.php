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

use Override;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\RawResultInterface;
use Symfony\AI\Platform\Result\StreamResult;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsageInterface;

/**
 * Returns the usage a drained stream reported, so even an unusable answer is
 * booked at its bill; an answer given in one piece keeps its call's usage.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class StreamedTokenUsageExtractor implements TokenUsageExtractorInterface
{
    public function __construct(
        private DeferredResult $streamedResult,
        private BufferedResend $bufferedResend,
    ) {}

    #[Override]
    public function extract(RawResultInterface $rawResult, array $options = []): ?TokenUsageInterface
    {
        if (UnstreamedAnswer::in($this->streamedResult)) {
            $answeringResult = $this->bufferedResend->answering($this->streamedResult);

            return $answeringResult->getResultConverter()->getTokenUsageExtractor()?->extract($answeringResult->getRawResult(), $options);
        }

        $answer = $this->streamedResult->getResult();
        $tokenUsage = ($answer instanceof StreamResult ? $answer->getMetadata() : $this->streamedResult->getMetadata())->get('token_usage');

        return $tokenUsage instanceof TokenUsageInterface ? $tokenUsage : null;
    }
}
