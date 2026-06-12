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
    private const int JSON_MAX_DEPTH = 512;

    private function __construct(
        private string $content,
        private int $inputTokens,
        private int $outputTokens,
        private string $model,
        private string $stopReason,
        private int $cacheReadTokens,
        private int $cacheCreationTokens,
    ) {}

    public static function create(
        string $content,
        int $inputTokens,
        int $outputTokens,
        string $model,
        string $stopReason,
        int $cacheReadTokens = 0,
        int $cacheCreationTokens = 0,
    ): self {
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

        try {
            $decoded = json_decode($content, true, self::JSON_MAX_DEPTH, \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            $decoded = $this->recoverDecodedJsonBlock($content) ?? throw $jsonException;
        }

        if (!\is_array($decoded)) {
            throw new RuntimeException('LLM response did not decode to array');
        }

        return $decoded;
    }

    /**
     * Walks every `[`/`{` position outside JSON string literals and returns the
     * first balanced block that decodes as JSON, or `null` when none do.
     *
     * When the content itself spans a single balanced block (`[ ... ]` or
     * `{ ... }` with no surrounding prose), the top-level `json_decode` has
     * already attempted exactly that payload — re-trying nested openers within
     * it would silently accept shallower inner blocks (defeating depth limits,
     * for one), so recovery is skipped in that case.
     *
     * Returns the decoded value as `mixed` so the existing not-array guard in
     * `parseJson` remains the single place that enforces the array contract.
     */
    private function recoverDecodedJsonBlock(string $content): mixed
    {
        if ($this->contentIsSingleBalancedBlock($content)) {
            return null;
        }

        $length = \strlen($content);
        $inString = false;
        $escape = false;

        for ($i = 0; $i < $length; ++$i) {
            $char = $content[$i];

            if ($escape) {
                $escape = false;
                continue;
            }

            if ($inString) {
                if ('\\' === $char) {
                    $escape = true;
                } elseif ('"' === $char) {
                    $inString = false;
                }

                continue;
            }

            if ('"' === $char) {
                $inString = true;
                continue;
            }

            if ('[' === $char) {
                $candidate = $this->tryDecodeBalancedBlock($content, $i, '[', ']');
            } elseif ('{' === $char) {
                $candidate = $this->tryDecodeBalancedBlock($content, $i, '{', '}');
            } else {
                continue;
            }

            if (null !== $candidate) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * True when `$content` starts with an opener and `scanBalancedBlockFrom`
     * consumes the entire string — meaning the original top-level `json_decode`
     * call already saw exactly this payload.
     */
    private function contentIsSingleBalancedBlock(string $content): bool
    {
        if ('' === $content) {
            return false;
        }

        $first = $content[0];
        if ('[' === $first) {
            $block = $this->scanBalancedBlockFrom($content, 0, '[', ']');
        } elseif ('{' === $first) {
            $block = $this->scanBalancedBlockFrom($content, 0, '{', '}');
        } else {
            return false;
        }

        return null !== $block && \strlen($block) === \strlen($content);
    }

    /**
     * Scans a balanced block starting at `$start` and attempts to JSON-decode it.
     * Returns the decoded value on success, or `null` when scanning hits EOF or
     * decoding fails — the caller iterates to the next opener candidate.
     */
    private function tryDecodeBalancedBlock(string $content, int $start, string $open, string $close): mixed
    {
        $block = $this->scanBalancedBlockFrom($content, $start, $open, $close);
        if (null === $block) {
            return null;
        }

        try {
            return json_decode($block, true, self::JSON_MAX_DEPTH, \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
    }

    private function scanBalancedBlockFrom(string $content, int $start, string $open, string $close): ?string
    {
        $length = \strlen($content);
        $depth = 0;
        $inString = false;
        $escape = false;

        for ($i = $start; $i < $length; ++$i) {
            $char = $content[$i];

            if ($escape) {
                $escape = false;
                continue;
            }

            if ($inString) {
                if ('\\' === $char) {
                    $escape = true;
                } elseif ('"' === $char) {
                    $inString = false;
                }

                continue;
            }

            if ('"' === $char) {
                $inString = true;
            } elseif ($char === $open) {
                ++$depth;
            } elseif ($char === $close) {
                --$depth;
                if (0 === $depth) {
                    return substr($content, $start, $i - $start + 1);
                }
            }
        }

        return null;
    }

    public function isEmpty(): bool
    {
        return '' === trim($this->content);
    }
}
