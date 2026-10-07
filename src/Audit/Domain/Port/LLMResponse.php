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
     * answer: output cut by the token limit, suppressed by a content filter,
     * a tool loop stopped at its iteration cap, a call that produced no
     * content at all, or a request the model could not take in.
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
     * The same response carrying the model the provider says answered it,
     * which a gateway or a failover platform may pick on its own. Null when
     * the provider reports none.
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
        );
    }

    public function reportedModel(): ?string
    {
        return $this->reportedModel;
    }

    public function totalTokens(): int
    {
        return $this->inputTokens + $this->outputTokens + $this->cacheReadTokens + $this->cacheCreationTokens;
    }

    /**
     * Returns the decoded JSON as an array. Shape varies (list of objects or single object),
     * so callers narrow with their own `@var` annotation. PHPStan requires a value type here;
     * `array<array-key, mixed>` is the most truthful expression of "any array".
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
     * Whether the answer was cut short (see `DEGRADED_STOP_REASONS`), in
     * which case an empty or partial payload is not the model's verdict and
     * must never be cached or reported as one.
     */
    public function isDegraded(): bool
    {
        return \in_array($this->stopReason, self::DEGRADED_STOP_REASONS, true);
    }

    /**
     * Whether the provider refused the request because the prompt alone
     * exceeds the model's input window — the content carries the refusal. A
     * batch client answers this per request where a single call throws, so
     * the caller can split the work; it is degraded too, so no consumer
     * counts it as a verdict.
     */
    public function isRequestTooLarge(): bool
    {
        return self::REQUEST_TOO_LARGE_STOP_REASON === $this->stopReason;
    }
}
