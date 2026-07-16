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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\FinishReason\FinishReasonCase;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResultExtractor;

final class PlatformResultExtractorTest extends TestCase
{
    public function test_it_extracts_the_raw_provider_stop_reason(): void
    {
        $platformResultExtractor = new PlatformResultExtractor(null);

        $stopReason = $platformResultExtractor->extractStopReason(
            $this->deferredResultWithFinishReason(new FinishReason(FinishReasonCase::STOP, 'end_turn')),
        );

        self::assertSame('end_turn', $stopReason);
    }

    public function test_it_returns_null_when_the_result_carries_no_finish_reason(): void
    {
        $platformResultExtractor = new PlatformResultExtractor(null);

        self::assertNull($platformResultExtractor->extractStopReason($this->deferredResult()));
    }

    public function test_it_warns_when_the_response_was_truncated_by_the_output_token_limit(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('truncated'),
                ['finish_reason' => 'max_tokens'],
            );

        $platformResultExtractor = new PlatformResultExtractor(null, $logger);

        $stopReason = $platformResultExtractor->extractStopReason(
            $this->deferredResultWithFinishReason(new FinishReason(FinishReasonCase::LENGTH, 'max_tokens')),
        );

        self::assertSame('max_tokens', $stopReason);
    }

    public function test_it_warns_when_the_response_was_suppressed_by_the_content_filter(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('content filter'),
                ['finish_reason' => 'content_filtered'],
            );

        $platformResultExtractor = new PlatformResultExtractor(null, $logger);

        $stopReason = $platformResultExtractor->extractStopReason(
            $this->deferredResultWithFinishReason(new FinishReason(FinishReasonCase::CONTENT_FILTER, 'content_filtered')),
        );

        self::assertSame('content_filtered', $stopReason);
    }

    public function test_it_does_not_warn_on_a_normal_stop(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');

        $platformResultExtractor = new PlatformResultExtractor(null, $logger);

        $stopReason = $platformResultExtractor->extractStopReason(
            $this->deferredResultWithFinishReason(new FinishReason(FinishReasonCase::TOOL_CALL, 'tool_use')),
        );

        self::assertSame('tool_use', $stopReason);
    }

    private function deferredResultWithFinishReason(FinishReason $finishReason): DeferredResult
    {
        $deferredResult = $this->deferredResult();
        $deferredResult->getMetadata()->add('finish_reason', $finishReason);

        return $deferredResult;
    }

    private function deferredResult(): DeferredResult
    {
        return new DeferredResult(
            new PlainConverter(new TextResult('ok')),
            new InMemoryRawResult([], [], (object) []),
        );
    }
}
