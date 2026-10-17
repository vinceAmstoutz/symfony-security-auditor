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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * Where the nodes one line of YAML, without its line break, opens begin: the
 * first at its indentation, then every `-` or `?` marker and every `key:` the
 * line opens on the line of its parent, as in `- - item`, `- key: value` or
 * `<<: - item`, skipping the `&anchor` and `!tag` before them. It errs towards
 * more levels than the parser opens: a colon inside a quoted value counts too.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class YamlLineNodes
{
    private const string BLANKS_AND_PROPERTIES = '/\G[ \t]*+(?:[&!][^ \t]*+[ \t]*+)*+/';

    private const string MARKERS = '-?';

    private const string NOT_A_KEY = '[{#';

    private const string KEY_COLON = '/:(?:[ \t]++|$)/';

    /**
     * @param int $limit how many nodes past the first are worth finding: the line is read no further once it opens that many more
     *
     * @return list<int> none for a blank or comment line
     */
    public static function columnsOf(string $line, int $limit): array
    {
        $indentation = strspn($line, ' ');
        if (self::opensNothing(substr($line, $indentation))) {
            return [];
        }

        $columns = [$indentation];
        $position = self::contentFrom($line, $indentation);
        $end = self::nodeEnd($line, $position);
        for ($found = 0; null !== $end && $found <= $limit; ++$found) {
            $columns = $position > $indentation ? [...$columns, $position] : $columns;
            $position = self::contentFrom($line, $end);
            $end = self::nodeEnd($line, $position);
        }

        return $columns;
    }

    private static function opensNothing(string $content): bool
    {
        return '' === trim($content) || str_starts_with($content, '#');
    }

    private static function contentFrom(string $line, int $position): int
    {
        preg_match(self::BLANKS_AND_PROPERTIES, $line, $matches, 0, $position);

        return $position + \strlen($matches[0] ?? '');
    }

    private static function nodeEnd(string $line, int $position): ?int
    {
        if (1 === strspn($line, self::NOT_A_KEY, $position, 1)) {
            return null;
        }

        return 1 === strspn($line, self::MARKERS, $position, 1) ? $position + 1 : self::keyEnd($line, $position);
    }

    private static function keyEnd(string $line, int $position): ?int
    {
        return 1 === preg_match(self::KEY_COLON, $line, $matches, \PREG_OFFSET_CAPTURE, $position) ? $matches[0][1] + \strlen($matches[0][0]) : null;
    }
}
