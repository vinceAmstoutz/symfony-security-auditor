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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use JsonException;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;

final readonly class LLMResponse
{
    /**
     * Stop reasons after which the response is not the model's complete
     * answer: cut by the token limit, filtered, stopped at the tool-loop cap,
     * empty or refused as too large.
     */
    private const array DEGRADED_STOP_REASONS = ['length', 'content-filter', 'max_tool_iterations', 'empty_content', self::REQUEST_TOO_LARGE_STOP_REASON];

    private const string REQUEST_TOO_LARGE_STOP_REASON = 'request_too_large';

    private function __construct(
        private string $content,
        private int $inputTokens,
        private int $outputTokens,
        private string $model,
        private string $stopReason,
        private int $cacheReadTokens,
        private int $cacheCreationTokens,
        private ?string $reportedModel = null,
        private bool $reachedToolCap = false,
    ) {}

    public static function of(
        string $content,
        string $model,
        string $stopReason,
        TokenUsageSnapshot $tokenUsageSnapshot,
    ): self {
        return new self(
            $content,
            $tokenUsageSnapshot->inputTokens(),
            $tokenUsageSnapshot->outputTokens(),
            $model,
            $stopReason,
            $tokenUsageSnapshot->cacheReadTokens(),
            $tokenUsageSnapshot->cacheCreationTokens(),
        );
    }

    /**
     * @deprecated since 1.13, use {@see self::of()} with a TokenUsageSnapshot instead.
     */
    public static function create(
        string $content,
        int $inputTokens,
        int $outputTokens,
        string $model,
        string $stopReason,
        int $cacheReadTokens = 0,
        int $cacheCreationTokens = 0,
    ): self {
        trigger_deprecation('vinceamstoutz/symfony-security-auditor', '1.13', 'LLMResponse::create() is deprecated, use LLMResponse::of() instead.');

        return new self($content, $inputTokens, $outputTokens, $model, $stopReason, $cacheReadTokens, $cacheCreationTokens);
    }

    public function content(): string
    {
        return $this->content;
    }

    public function inputTokens(): int
    {
        return $this->inputTokens;
    }

    public function outputTokens(): int
    {
        return $this->outputTokens;
    }

    public function cacheReadTokens(): int
    {
        return $this->cacheReadTokens;
    }

    public function cacheCreationTokens(): int
    {
        return $this->cacheCreationTokens;
    }

    public function model(): string
    {
        return $this->model;
    }

    public function stopReason(): string
    {
        return $this->stopReason;
    }

    /**
     * Carries the model the provider says answered, which a gateway or a
     * failover platform may pick; null when the provider reports none.
     */
    public function withReportedModel(?string $reportedModel): self
    {
        return new self(
            $this->content,
            $this->inputTokens,
            $this->outputTokens,
            $this->model,
            $this->stopReason,
            $this->cacheReadTokens,
            $this->cacheCreationTokens,
            $reportedModel,
            $this->reachedToolCap,
        );
    }

    public function reportedModel(): ?string
    {
        return $this->reportedModel;
    }

    /**
     * Marks the answer of a tool conversation that reached its last allowed
     * round: if it found nothing, it is no verdict.
     */
    public function withReachedToolCap(): self
    {
        return new self(
            $this->content,
            $this->inputTokens,
            $this->outputTokens,
            $this->model,
            $this->stopReason,
            $this->cacheReadTokens,
            $this->cacheCreationTokens,
            $this->reportedModel,
            true,
        );
    }

    public function reachedToolCap(): bool
    {
        return $this->reachedToolCap;
    }

    public function totalTokens(): int
    {
        return $this->inputTokens + $this->outputTokens + $this->cacheReadTokens + $this->cacheCreationTokens;
    }

    /**
     * Returns the decoded JSON: a list of objects or a single object.
     *
     * @return array<array-key, mixed>
     *
     * @throws JsonException    when content is not valid JSON
     * @throws RuntimeException when JSON does not decode to an array
     */
    public function parseJson(): array
    {
        $decoded = LLMAnswerJsonDecoder::decode($this->content);

        if (!\is_array($decoded)) {
            throw new RuntimeException('LLM response did not decode to array');
        }

        return $decoded;
    }

    public function isEmpty(): bool
    {
        return '' === trim($this->content);
    }

    /**
     * Whether the answer was cut short (`DEGRADED_STOP_REASONS`): its payload
     * must never be cached or reported as a verdict.
     */
    public function isDegraded(): bool
    {
        return \in_array($this->stopReason, self::DEGRADED_STOP_REASONS, true);
    }

    /**
     * Whether the provider refused the request because the prompt alone
     * exceeds the model's input window; the content carries the refusal. A
     * batch client answers so per request where a single call throws. Also
     * degraded.
     */
    public function isRequestTooLarge(): bool
    {
        return self::REQUEST_TOO_LARGE_STOP_REASON === $this->stopReason;
    }
}
