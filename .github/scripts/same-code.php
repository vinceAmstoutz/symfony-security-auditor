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

// Exits 0 when the two PHP files given hold the same code, comments and whitespace aside, for plan-binary-build.sh.

$code = static fn (string $file): array => array_values(array_map(
    static fn (array|string $token): string => is_array($token) ? token_name($token[0]).':'.$token[1] : $token,
    array_filter(
        token_get_all((string) file_get_contents($file)),
        static fn (array|string $token): bool => !is_array($token) || !in_array($token[0], [T_COMMENT, T_DOC_COMMENT, T_WHITESPACE], true),
    ),
));

exit($code($argv[1]) === $code($argv[2]) ? 0 : 1);
