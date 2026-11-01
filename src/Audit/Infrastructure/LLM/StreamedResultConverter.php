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

    public function __construct(private DeferredResult $streamedResult) {}

    #[Override]
    public function supports(Model $model): bool
    {
        return true;
    }

    /**
     * @throws EmptyStreamedAnswerException when the stream carried no content
     */
    #[Override]
    public function convert(RawResultInterface $result, array $options = []): ResultInterface
    {
        $streamResult = $this->streamedResult->getResult();
        \assert($streamResult instanceof StreamResult);

        $bufferedResult = $this->bufferedResult($streamResult->getAssistantMessage());
        $bufferedResult->getMetadata()->merge($streamResult->getMetadata());
        $bufferedResult->getMetadata()->remove(self::TOKEN_USAGE);

        return $bufferedResult;
    }

    #[Override]
    public function getTokenUsageExtractor(): TokenUsageExtractorInterface
    {
        return new StreamedTokenUsageExtractor($this->streamedResult);
    }

    /**
     * @throws EmptyStreamedAnswerException
     */
    private function bufferedResult(AssistantMessage $assistantMessage): ResultInterface
    {
        $parts = $this->resultParts($assistantMessage);

        return [] === $parts ? throw EmptyStreamedAnswerException::create() : new MultiPartResult($parts);
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
