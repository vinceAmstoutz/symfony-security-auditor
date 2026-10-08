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

/**
 * Reads the JSON a model answered with, recovering it from the prose or the
 * truncation a model may wrap around it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LLMAnswerJsonDecoder
{
    private const int JSON_MAX_DEPTH = 512;

    private const int MAX_RECOVERY_CANDIDATES = 64;

    /**
     * Returns the decoded value as `mixed` so the not-array guard in
     * `LLMResponse::parseJson` remains the single place that enforces the
     * array contract.
     *
     * @throws JsonException when the answer is not valid JSON and holds no block that decodes
     */
    public static function decode(string $answer): mixed
    {
        $content = self::withoutWrappingFence($answer);

        try {
            return json_decode($content, true, self::JSON_MAX_DEPTH, \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            return self::recoverDecodedJsonBlock($content) ?? throw $jsonException;
        }
    }

    /**
     * Only a Markdown fence around the whole answer is stripped: the same
     * backticks inside a JSON string, such as a finding quoting a code block,
     * are part of the payload.
     */
    private static function withoutWrappingFence(string $content): string
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
     * first complete object of that array), or `null` when none do, among the
     * first {@see self::MAX_RECOVERY_CANDIDATES} openers only. A JSON
     * object written after the answer still stands for it: nothing here knows
     * the shape the caller expects.
     *
     * When the content itself spans a single balanced block (`[ ... ]` or
     * `{ ... }` with no surrounding prose), the top-level `json_decode` has
     * already attempted exactly that payload — re-trying nested openers within
     * it would silently accept shallower inner blocks (defeating depth limits,
     * for one), so recovery is skipped in that case.
     */
    private static function recoverDecodedJsonBlock(string $content): mixed
    {
        if (BalancedBlockScanner::contentIsSingleBalancedBlock($content)) {
            return null;
        }

        $openerPositions = BalancedBlockScanner::openerPositions($content);

        return self::lastDecodedBlock(self::topLevelBlocks($content, $openerPositions))
            ?? self::firstDecodedBlock($content, $openerPositions);
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
    private static function topLevelBlocks(string $content, array $openerPositions): array
    {
        $blocks = [];

        foreach ($openerPositions as $openerPosition) {
            if (self::opensInsideLastBlock($blocks, $openerPosition)) {
                continue;
            }

            $block = BalancedBlockScanner::balancedBlockOpenedAt($content, $openerPosition);
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
    private static function opensInsideLastBlock(array $blocks, int $position): bool
    {
        $lastBlockPosition = array_key_last($blocks);

        return null !== $lastBlockPosition && $position < $lastBlockPosition + \strlen($blocks[$lastBlockPosition]);
    }

    /**
     * @param array<int, string> $blocks
     */
    private static function lastDecodedBlock(array $blocks): mixed
    {
        foreach (array_reverse($blocks) as $block) {
            $decoded = self::decodeBlock($block);
            if (\is_array($decoded) && self::canStandForTheAnswer($decoded)) {
                return $decoded;
            }
        }

        return null;
    }

    /**
     * An object, or a list holding one. Anything else is what prose brackets
     * decode to — `[1]` citing a source, `[ ]` in a checklist, `[[12, 14]]`
     * listing line ranges — so it never outranks an earlier block.
     *
     * @param array<mixed> $decoded
     */
    private static function canStandForTheAnswer(array $decoded): bool
    {
        return !array_is_list($decoded) || [] !== array_filter($decoded, self::isObject(...));
    }

    private static function isObject(mixed $element): bool
    {
        return \is_array($element) && !array_is_list($element);
    }

    /**
     * @param list<int> $openerPositions
     */
    private static function firstDecodedBlock(string $content, array $openerPositions): mixed
    {
        foreach (\array_slice($openerPositions, 0, self::MAX_RECOVERY_CANDIDATES) as $openerPosition) {
            $block = BalancedBlockScanner::balancedBlockOpenedAt($content, $openerPosition);
            $decoded = null === $block ? null : self::decodeBlock($block);
            if (null !== $decoded) {
                return $decoded;
            }
        }

        return null;
    }

    /**
     * The decoded block, or `null` when it does not decode — the caller moves
     * on to the next candidate.
     */
    private static function decodeBlock(string $block): mixed
    {
        try {
            return json_decode($block, true, self::JSON_MAX_DEPTH, \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
    }
}
