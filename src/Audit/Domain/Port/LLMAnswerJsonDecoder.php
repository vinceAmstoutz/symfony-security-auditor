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
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class LLMAnswerJsonDecoder
{
    private const int JSON_MAX_DEPTH = 512;

    private const int MAX_RECOVERY_CANDIDATES = 64;

    /**
     * Returns any decoded value: `LLMResponse::parseJson()` enforces the array
     * contract.
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
     * Whether the answer's JSON is one value alone: the only top-level block
     * that can stand for it, with no block left open after it. Otherwise
     * `decode()` returns only one of several.
     */
    public static function holdsOneValue(string $answer): bool
    {
        $content = self::withoutWrappingFence($answer);
        $openerPositions = BalancedBlockScanner::openerPositions($content);
        $blocks = self::topLevelBlocks($content, $openerPositions);

        return 1 === \count(array_filter($blocks, self::standsForTheAnswer(...)))
            && self::opensInsideLastBlock($blocks, (int) end($openerPositions));
    }

    /**
     * Strips only a Markdown fence around the whole answer: backticks inside a
     * JSON string belong to the payload.
     */
    private static function withoutWrappingFence(string $content): string
    {
        return trim((string) preg_replace(['/\A\s*```(?:json)?/', '/```\s*\z/'], '', $content));
    }

    /**
     * The last top-level balanced block that decodes to an object or a list
     * holding one, so JSON quoted while reasoning never stands for the verdict
     * after it. Else the first balanced block anywhere that decodes, such as
     * the first complete object of an array the output limit cut off, among
     * the first {@see self::MAX_RECOVERY_CANDIDATES} openers; null when none
     * does. Nothing is recovered from content that is a single balanced block,
     * which `json_decode` already tried: an inner block must not pass for it.
     */
    private static function recoverDecodedJsonBlock(string $content): mixed
    {
        if (BalancedBlockScanner::contentIsSingleBalancedBlock($content)) {
            return null;
        }

        $openerPositions = BalancedBlockScanner::openerPositions($content);

        return self::lastDecodedBlock(self::topLevelBlocks($content, $openerPositions))
            ?? self::firstDecodedBlock($content, self::recoveryCandidates($openerPositions));
    }

    /**
     * The openers searched for the first block that decodes anywhere, each
     * scanned up to the end of the answer at most: the first
     * {@see self::MAX_RECOVERY_CANDIDATES} of `$openerPositions`.
     *
     * @param list<int> $openerPositions
     *
     * @return list<int>
     */
    public static function recoveryCandidates(array $openerPositions): array
    {
        return \array_slice($openerPositions, 0, self::MAX_RECOVERY_CANDIDATES);
    }

    /**
     * The balanced blocks those openers start outside any other block, in
     * order, up to the first opener that never closes.
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
     * An object or a list holding one. Anything else is what prose brackets
     * decode to (`[1]`, `[ ]`, `[[12, 14]]`), which never outranks an earlier
     * block.
     *
     * @param array<mixed> $decoded
     */
    private static function canStandForTheAnswer(array $decoded): bool
    {
        return !array_is_list($decoded) || [] !== array_filter($decoded, self::isObject(...));
    }

    private static function standsForTheAnswer(string $block): bool
    {
        $decoded = self::decodeBlock($block);

        return \is_array($decoded) && self::canStandForTheAnswer($decoded);
    }

    private static function isObject(mixed $element): bool
    {
        return \is_array($element) && !array_is_list($element);
    }

    /**
     * @param list<int> $recoveryCandidates
     */
    private static function firstDecodedBlock(string $content, array $recoveryCandidates): mixed
    {
        foreach ($recoveryCandidates as $openerPosition) {
            $block = BalancedBlockScanner::balancedBlockOpenedAt($content, $openerPosition);
            $decoded = null === $block ? null : self::decodeBlock($block);
            if (null !== $decoded) {
                return $decoded;
            }
        }

        return null;
    }

    /**
     * The decoded block, or null when it does not decode.
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
