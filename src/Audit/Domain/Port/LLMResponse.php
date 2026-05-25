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
        try {
            $decoded = json_decode($content, true, 512, \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            // When tools are enabled the LLM sometimes returns prose around the JSON
            // despite the "Return ONLY the JSON array" prompt instruction. Try to
            // recover the first balanced `[ ... ]` / `{ ... }` block before giving up.
            $extracted = $this->extractBalancedJsonBlock($content);
            if (null === $extracted) {
                throw $jsonException;
            }

            $decoded = json_decode($extracted, true, 512, \JSON_THROW_ON_ERROR);
        }

        if (!\is_array($decoded)) {
            throw new RuntimeException('LLM response did not decode to array');
        }

        return $decoded;
    }

    /**
     * Returns the first balanced `[ ... ]` or `{ ... }` substring, or `null` when no
     * top-level block closes. Walks the string char-by-char while respecting JSON
     * string literals (and their `\"` escapes) so brackets inside strings do not
     * affect depth counting.
     */
    private function extractBalancedJsonBlock(string $content): ?string
    {
        $length = \strlen($content);
        $start = -1;
        $open = '';
        $close = '';

        for ($i = 0; $i < $length; ++$i) {
            $char = $content[$i];
            if ('[' === $char || '{' === $char) {
                $start = $i;
                $open = $char;
                $close = '[' === $char ? ']' : '}';
                break;
            }
        }

        if (-1 === $start) {
            return null;
        }

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
