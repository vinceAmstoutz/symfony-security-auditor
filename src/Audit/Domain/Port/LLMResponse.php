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
    private const int JSON_MAX_DEPTH = 512;

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
        $content = $this->withoutWrappingFence($this->content);

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
     * Only a Markdown fence around the whole answer is stripped: the same
     * backticks inside a JSON string, such as a finding quoting a code block,
     * are part of the payload.
     */
    private function withoutWrappingFence(string $content): string
    {
        return trim((string) preg_replace(['/\A\s*```(?:json)?/', '/```\s*\z/'], '', $content));
    }

    /**
     * Takes the last balanced block at the top level of the answer that
     * decodes to an object or to a list holding one: a model that reasons
     * before its verdict may quote JSON — from the audited code, say — that
     * must not stand for the verdict that follows it, and a bracket in the
     * prose after its answer must not either. When no top-level block
     * qualifies, as when the output limit cut an array off before its closing
     * bracket, the first balanced block anywhere that decodes is taken (the
     * first complete object of that array), or `null` when none do. A JSON
     * object written after the answer still stands for it: nothing here knows
     * the shape the caller expects.
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

        $openerPositions = $this->openerPositions($content, $this->hasBalancedQuotes($content));

        return $this->lastDecodedBlock($this->topLevelBlocks($content, $openerPositions))
            ?? $this->firstDecodedBlock($content, $openerPositions);
    }

    /**
     * The position of every `[`/`{` outside a JSON string, in order.
     *
     * @return list<int>
     */
    private function openerPositions(string $content, bool $trackStringLiterals): array
    {
        $positions = [];
        $state = ['inString' => false, 'escape' => false];

        foreach (str_split($content) as $position => $char) {
            $next = $this->advanceIfTrackingStringLiterals($trackStringLiterals, $char, $state);
            $state = ['inString' => $next['inString'], 'escape' => $next['escape']];

            if (!$next['consumed'] && $this->isOpener($char)) {
                $positions[] = $position;
            }
        }

        return $positions;
    }

    /**
     * The balanced blocks those openers start outside any other block, in
     * order. An opener that never closes holds the rest of the answer, so the
     * scan stops there.
     *
     * @param list<int> $openerPositions
     *
     * @return array<int, string> keyed by the position each block opens at
     */
    private function topLevelBlocks(string $content, array $openerPositions): array
    {
        $blocks = [];

        foreach ($openerPositions as $openerPosition) {
            if ($this->opensInsideLastBlock($blocks, $openerPosition)) {
                continue;
            }

            $block = $this->balancedBlockOpenedAt($content, $openerPosition);
            if (null === $block) {
                break;
            }

            $blocks[$openerPosition] = $block;
        }

        return $blocks;
    }

    /**
     * @param array<int, string> $blocks keyed by the position each block opens at
     */
    private function opensInsideLastBlock(array $blocks, int $position): bool
    {
        $lastBlockPosition = array_key_last($blocks);

        return null !== $lastBlockPosition && $position < $lastBlockPosition + \strlen($blocks[$lastBlockPosition]);
    }

    /**
     * @param array<int, string> $blocks
     */
    private function lastDecodedBlock(array $blocks): mixed
    {
        foreach (array_reverse($blocks) as $block) {
            $decoded = $this->decodeBlock($block);
            if (\is_array($decoded) && $this->canStandForTheAnswer($decoded)) {
                return $decoded;
            }
        }

        return null;
    }

    /**
     * An object, or a list holding an object or an array. An empty list or a
     * list of scalars is what prose brackets decode to — `[1]` citing a
     * source, `[ ]` in a checklist — so it never outranks an earlier block.
     *
     * @param array<mixed> $decoded
     */
    private function canStandForTheAnswer(array $decoded): bool
    {
        return !array_is_list($decoded) || [] !== array_filter($decoded, \is_array(...));
    }

    /**
     * @param list<int> $openerPositions
     */
    private function firstDecodedBlock(string $content, array $openerPositions): mixed
    {
        foreach ($openerPositions as $openerPosition) {
            $block = $this->balancedBlockOpenedAt($content, $openerPosition);
            $decoded = null === $block ? null : $this->decodeBlock($block);
            if (null !== $decoded) {
                return $decoded;
            }
        }

        return null;
    }

    /**
     * Delegates to {@see self::advanceStringLiteralState()} only when the
     * content's quotes are genuinely paired — otherwise every character is
     * reported as not consumed, so `recoverDecodedJsonBlock` tries every
     * `[`/`{` position directly instead of relying on a toggle a stray
     * unpaired quote would desync (see {@see self::hasBalancedQuotes()}).
     *
     * @param array{inString: bool, escape: bool} $state
     *
     * @return array{inString: bool, escape: bool, consumed: bool}
     */
    private function advanceIfTrackingStringLiterals(bool $trackStringLiterals, string $char, array $state): array
    {
        if (!$trackStringLiterals) {
            return [...$state, 'consumed' => false];
        }

        return $this->advanceStringLiteralState($char, $state['inString'], $state['escape']);
    }

    /**
     * An unescaped double-quote toggles "inside a string" on and off as
     * `recoverDecodedJsonBlock` scans for genuine `[`/`{` openers —
     * meant to skip a bracket embedded in a quoted prose phrase (see
     * `test_it_skips_a_leading_quoted_string_with_escaped_bracket_before_the_real_array`).
     * That toggle only makes sense when every quote in the content is
     * genuinely paired; a single unpaired literal quote before the real
     * JSON (e.g. a measurement like `5"`) would otherwise flip the running
     * state permanently, hiding every opener after it — including the real
     * one. Running the same state machine across the whole content and
     * checking whether it ends still "inside a string" detects that case,
     * so the scan can fall back to trying every opener directly instead.
     */
    private function hasBalancedQuotes(string $content): bool
    {
        $length = \strlen($content);
        $inString = false;
        $escape = false;

        for ($i = 0; $i < $length; ++$i) {
            $next = $this->advanceStringLiteralState($content[$i], $inString, $escape);
            $inString = $next['inString'];
            $escape = $next['escape'];
        }

        return !$inString;
    }

    private function isOpener(string $char): bool
    {
        return '[' === $char || '{' === $char;
    }

    private function balancedBlockOpenedAt(string $content, int $start): ?string
    {
        return '[' === $content[$start]
            ? $this->scanBalancedBlockFrom($content, $start, '[', ']')
            : $this->scanBalancedBlockFrom($content, $start, '{', '}');
    }

    /**
     * Advances the string-literal scanning state for a single character.
     *
     * `consumed` is true when the character belongs to string-literal handling
     * (an escape, a quote, or any character inside a string) and the caller must
     * skip its own structural handling for it.
     *
     * @return array{inString: bool, escape: bool, consumed: bool}
     */
    private function advanceStringLiteralState(string $char, bool $inString, bool $escape): array
    {
        if ($escape) {
            return ['inString' => $inString, 'escape' => false, 'consumed' => true];
        }

        if ($inString) {
            return [
                'inString' => '"' !== $char,
                'escape' => '\\' === $char,
                'consumed' => true,
            ];
        }

        $opensString = '"' === $char;

        return ['inString' => $opensString, 'escape' => false, 'consumed' => $opensString];
    }

    /**
     * True when `$content` starts with an opener and `scanBalancedBlockFrom`
     * consumes the entire string — meaning the original top-level `json_decode`
     * call already saw exactly this payload.
     */
    private function contentIsSingleBalancedBlock(string $content): bool
    {
        $block = match ($content[0] ?? '') {
            '[' => $this->scanBalancedBlockFrom($content, 0, '[', ']'),
            '{' => $this->scanBalancedBlockFrom($content, 0, '{', '}'),
            default => null,
        };

        if (null === $block) {
            return false;
        }

        return \strlen($block) === \strlen($content);
    }

    /**
     * The decoded block, or `null` when it does not decode — the caller moves
     * on to the next candidate.
     */
    private function decodeBlock(string $block): mixed
    {
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

            $next = $this->advanceStringLiteralState($char, $inString, $escape);
            $inString = $next['inString'];
            $escape = $next['escape'];

            if ($next['consumed']) {
                continue;
            }

            $depth = $this->adjustDepth($depth, $char, $open, $close);

            if ($char === $close && 0 === $depth) {
                return substr($content, $start, $i - $start + 1);
            }
        }

        return null;
    }

    private function adjustDepth(int $depth, string $char, string $open, string $close): int
    {
        if ($char === $open) {
            return $depth + 1;
        }

        if ($char === $close) {
            return $depth - 1;
        }

        return $depth;
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
