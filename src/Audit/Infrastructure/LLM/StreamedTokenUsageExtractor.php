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
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsageInterface;

/**
 * The usage a streamed answer reported, read once the stream was drained,
 * so even an answer that could not be used is booked at what it was billed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StreamedTokenUsageExtractor implements TokenUsageExtractorInterface
{
    public function __construct(private DeferredResult $streamedResult) {}

    #[Override]
    public function extract(RawResultInterface $rawResult, array $options = []): ?TokenUsageInterface
    {
        $tokenUsage = $this->streamedResult->getResult()->getMetadata()->get('token_usage');

        return $tokenUsage instanceof TokenUsageInterface ? $tokenUsage : null;
    }
}
