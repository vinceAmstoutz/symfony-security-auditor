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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StringLiteralMasker
{
    private const string STRING_LITERAL_PATTERN = '/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"/';

    public function mask(string $line): string
    {
        return preg_replace_callback(
            self::STRING_LITERAL_PATTERN,
            static fn (array $matches): string => str_repeat('x', \strlen($matches[0])),
            $line,
        ) ?? $line;
    }

    public function strip(string $line): string
    {
        return preg_replace(self::STRING_LITERAL_PATTERN, '', $line) ?? $line;
    }
}
