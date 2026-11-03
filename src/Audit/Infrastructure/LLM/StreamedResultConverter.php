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
use Symfony\AI\Platform\Message\AssistantMessage;
use Symfony\AI\Platform\Message\Content\Text;
use Symfony\AI\Platform\Message\Content\Thinking;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\RawResultInterface;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\StreamResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ThinkingResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\ResultConverterInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyStreamedAnswerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnfinishedStreamException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnmeteredStreamException;

/**
 * Reads a streamed answer to its end the first time it is asked for, and
 * gives it back as the result a buffered call would have produced, with the
 * finish reason the stream reported; its usage comes once, through
 * {@see StreamedTokenUsageExtractor}.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StreamedResultConverter implements ResultConverterInterface
{
    private const string TOKEN_USAGE = 'token_usage';

    private const string FINISH_REASON = 'finish_reason';

    public function __construct(
        private DeferredResult $streamedResult,
        private StreamMetering $streamMetering = new StreamMetering(),
    ) {}

    #[Override]
    public function supports(Model $model): bool
    {
        return true;
    }

    /**
     * @throws EmptyStreamedAnswerException when the stream carried no content
     * @throws UnfinishedStreamException    when the stream never said why the model stopped
     * @throws UnmeteredStreamException     when the stream never reported its usage
     */
    #[Override]
    public function convert(RawResultInterface $result, array $options = []): ResultInterface
    {
        $bufferedResult = UnstreamedAnswer::in($this->streamedResult) ? $this->unstreamedResult($options) : $this->streamedAnswer();
        $bufferedResult->getMetadata()->remove(self::TOKEN_USAGE);

        return $bufferedResult;
    }

    #[Override]
    public function getTokenUsageExtractor(): TokenUsageExtractorInterface
    {
        return new StreamedTokenUsageExtractor($this->streamedResult);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function unstreamedResult(array $options): ResultInterface
    {
        $this->streamMetering->stopStreaming();

        return $this->streamedResult->getResultConverter()->convert($this->streamedResult->getRawResult(), $options);
    }

    /**
     * @throws EmptyStreamedAnswerException
     * @throws UnfinishedStreamException
     * @throws UnmeteredStreamException
     */
    private function streamedAnswer(): ResultInterface
    {
        $answer = $this->streamedResult->getResult();

        return $answer instanceof StreamResult ? $this->bufferedResult($answer) : $answer;
    }

    /**
     * @throws EmptyStreamedAnswerException
     * @throws UnfinishedStreamException
     * @throws UnmeteredStreamException
     */
    private function bufferedResult(StreamResult $streamResult): ResultInterface
    {
        $parts = $this->resultParts($streamResult->getAssistantMessage());
        if (!$streamResult->getMetadata()->has(self::FINISH_REASON)) {
            throw UnfinishedStreamException::withoutFinishReason();
        }

        if (!$streamResult->getMetadata()->has(self::TOKEN_USAGE)) {
            $this->streamMetering->stopStreaming();

            throw UnmeteredStreamException::withoutUsage();
        }

        $bufferedResult = [] === $parts ? throw EmptyStreamedAnswerException::create() : new MultiPartResult($parts);
        $bufferedResult->getMetadata()->merge($streamResult->getMetadata());

        return $bufferedResult;
    }

    /**
     * @return list<ResultInterface>
     */
    private function resultParts(AssistantMessage $assistantMessage): array
    {
        $parts = [];
        foreach ($assistantMessage->getContent() as $content) {
            if ($content instanceof Thinking) {
                $parts[] = new ThinkingResult($content->getContent(), $content->getSignature());
            }

            if ($content instanceof Text) {
                $parts[] = new TextResult($content->getText());
            }

            if ($content instanceof ToolCall) {
                $parts[] = new ToolCallResult([$content]);
            }
        }

        return $parts;
    }
}
