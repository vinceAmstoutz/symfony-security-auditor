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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\FinishReason\FinishReasonCase;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResultExtractor;

final class PlatformResultExtractorTest extends TestCase
{
    /**
     * @throws NegativeTokenCountException
     */
    public function test_it_extracts_all_four_token_counts_with_no_recorder(): void
    {
        $platformResultExtractor = new PlatformResultExtractor(null);

        $tokens = $platformResultExtractor->extractTokens(
            $this->deferredResultWithTokenUsage(new TokenUsage(promptTokens: 10, completionTokens: 5, cacheCreationTokens: 2, cacheReadTokens: 3)),
        );

        self::assertSame([10, 5, 3, 2], $tokens);
    }

    /**
     * A negative count is a compromised or malfunctioning provider response.
     * `$tokenUsageRecorder` is optional and defaults to `null`
     * ({@see PlatformAccountingConfig}),
     * so this guard must reject the value itself rather than relying on the
     * recorder's own validation — every caller depends on it running before
     * the value ever reaches `RateLimiterInterface::record()`, whose
     * mutable window counters have no lower bound of their own.
     *
     * @throws NegativeTokenCountException
     */
    #[DataProvider('negativeTokenCases')]
    public function test_it_rejects_a_negative_token_count_with_no_recorder(TokenUsage $tokenUsage, string $expectedMessage): void
    {
        $platformResultExtractor = new PlatformResultExtractor(null);

        $this->expectException(NegativeTokenCountException::class);
        $this->expectExceptionMessage($expectedMessage);

        $platformResultExtractor->extractTokens($this->deferredResultWithTokenUsage($tokenUsage));
    }

    /** @return iterable<string, array{TokenUsage, string}> */
    public static function negativeTokenCases(): iterable
    {
        yield 'input tokens' => [new TokenUsage(promptTokens: -1, completionTokens: 0), 'Input tokens must be >= 0, got -1'];
        yield 'output tokens' => [new TokenUsage(promptTokens: 0, completionTokens: -1), 'Output tokens must be >= 0, got -1'];
        yield 'cache read tokens' => [new TokenUsage(promptTokens: 0, completionTokens: 0, cacheReadTokens: -1), 'Cache read tokens must be >= 0, got -1'];
        yield 'cache creation tokens' => [new TokenUsage(promptTokens: 0, completionTokens: 0, cacheCreationTokens: -1), 'Cache creation tokens must be >= 0, got -1'];
    }

    private function deferredResultWithTokenUsage(TokenUsage $tokenUsage): DeferredResult
    {
        $deferredResult = $this->deferredResult();
        $deferredResult->getMetadata()->add('token_usage', $tokenUsage);

        return $deferredResult;
    }

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
