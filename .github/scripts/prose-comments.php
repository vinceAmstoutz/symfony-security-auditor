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

// Prints every line of the comments and docblocks of the PHP file given as "<line>\t<placement>\t<text>", for check-prose.sh.

$tokens = token_get_all((string) file_get_contents($argv[1]));

foreach ($tokens as $index => $token) {
    if (!is_array($token) || !in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
        continue;
    }

    $before = $tokens[$index - 1] ?? null;
    $standalone = !is_array($before) || T_OPEN_TAG === $before[0] || (T_WHITESPACE === $before[0] && str_contains($before[1], "\n"));
    $placement = $standalone ? 'own-line' : 'trailing';

    foreach (explode("\n", $token[1]) as $offset => $text) {
        echo $token[2] + $offset, "\t", $placement, "\t", $text, "\n";
    }
}
