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

/**
 * Finds the `[ ... ]` and `{ ... }` blocks of a text, skipping the brackets a
 * JSON string literal holds.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BalancedBlockScanner
{
    /**
     * The position of every `[`/`{` outside a JSON string, in order.
     *
     * @return list<int>
     */
    public static function openerPositions(string $content): array
    {
        $trackStringLiterals = self::hasBalancedQuotes($content);
        $positions = [];
        $state = ['inString' => false, 'escape' => false];

        foreach (str_split($content) as $position => $char) {
            $next = self::advanceIfTrackingStringLiterals($trackStringLiterals, $char, $state);
            $state = ['inString' => $next['inString'], 'escape' => $next['escape']];

            if (!$next['consumed'] && self::isOpener($char)) {
                $positions[] = $position;
            }
        }

        return $positions;
    }

    public static function balancedBlockOpenedAt(string $content, int $start): ?string
    {
        return '[' === $content[$start]
            ? self::scanBalancedBlockFrom($content, $start, '[', ']')
            : self::scanBalancedBlockFrom($content, $start, '{', '}');
    }

    /**
     * True when `$content` starts with an opener and `scanBalancedBlockFrom`
     * consumes the entire string — meaning the original top-level `json_decode`
     * call already saw exactly this payload.
     */
    public static function contentIsSingleBalancedBlock(string $content): bool
    {
        $block = match ($content[0] ?? '') {
            '[' => self::scanBalancedBlockFrom($content, 0, '[', ']'),
            '{' => self::scanBalancedBlockFrom($content, 0, '{', '}'),
            default => null,
        };

        if (null === $block) {
            return false;
        }

        return \strlen($block) === \strlen($content);
    }

    /**
     * Delegates to {@see self::advanceStringLiteralState()} only when the
     * content's quotes are genuinely paired — otherwise every character is
     * reported as not consumed, so `openerPositions` tries every `[`/`{`
     * position directly instead of relying on a toggle a stray unpaired quote
     * would desync (see {@see self::hasBalancedQuotes()}).
     *
     * @param array{inString: bool, escape: bool} $state
     *
     * @return array{inString: bool, escape: bool, consumed: bool}
     */
    private static function advanceIfTrackingStringLiterals(bool $trackStringLiterals, string $char, array $state): array
    {
        if (!$trackStringLiterals) {
            return [...$state, 'consumed' => false];
        }

        return self::advanceStringLiteralState($char, $state['inString'], $state['escape']);
    }

    /**
     * An unescaped double-quote toggles "inside a string" on and off as
     * `openerPositions` scans for genuine `[`/`{` openers —
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
    private static function hasBalancedQuotes(string $content): bool
    {
        $length = \strlen($content);
        $inString = false;
        $escape = false;

        for ($i = 0; $i < $length; ++$i) {
            $next = self::advanceStringLiteralState($content[$i], $inString, $escape);
            $inString = $next['inString'];
            $escape = $next['escape'];
        }

        return !$inString;
    }

    private static function isOpener(string $char): bool
    {
        return '[' === $char || '{' === $char;
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
    private static function advanceStringLiteralState(string $char, bool $inString, bool $escape): array
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

    private static function scanBalancedBlockFrom(string $content, int $start, string $open, string $close): ?string
    {
        $length = \strlen($content);
        $depth = 0;
        $inString = false;
        $escape = false;

        for ($i = $start; $i < $length; ++$i) {
            $char = $content[$i];

            $next = self::advanceStringLiteralState($char, $inString, $escape);
            $inString = $next['inString'];
            $escape = $next['escape'];

            if ($next['consumed']) {
                continue;
            }

            $depth = self::adjustDepth($depth, $char, $open, $close);

            if ($char === $close && 0 === $depth) {
                return substr($content, $start, $i - $start + 1);
            }
        }

        return null;
    }

    private static function adjustDepth(int $depth, string $char, string $open, string $close): int
    {
        if ($char === $open) {
            return $depth + 1;
        }

        if ($char === $close) {
            return $depth - 1;
        }

        return $depth;
    }
}
