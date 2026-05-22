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

final readonly class LLMResponse
{
    private function __construct(
        private string $content,
        private int $inputTokens,
        private int $outputTokens,
        private string $model,
        private string $stopReason,
    ) {}

    public static function create(
        string $content,
        int $inputTokens,
        int $outputTokens,
        string $model,
        string $stopReason,
    ): self {
        return new self($content, $inputTokens, $outputTokens, $model, $stopReason);
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

    public function model(): string
    {
        return $this->model;
    }

    public function stopReason(): string
    {
        return $this->stopReason;
    }

    public function totalTokens(): int
    {
        return $this->inputTokens + $this->outputTokens;
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
        $content = $this->content;

        // Strip markdown fences that LLMs sometimes wrap JSON in
        $content = (string) preg_replace('/```json\s*/', '', $content);
        $content = (string) preg_replace('/```\s*/', '', $content);
        $content = trim($content);

        // Raw json_decode (over symfony/serializer) is deliberate: the LLM emits free-form
        // payloads whose shape we cannot pre-declare as a class. We only need array hydration
        // here; downstream factories (e.g. VulnerabilityFactory) handle structural validation.
        $decoded = json_decode($content, true, 512, \JSON_THROW_ON_ERROR);

        if (!\is_array($decoded)) {
            throw new RuntimeException('LLM response did not decode to array');
        }

        return $decoded;
    }

    public function isEmpty(): bool
    {
        return '' === trim($this->content);
    }
}
