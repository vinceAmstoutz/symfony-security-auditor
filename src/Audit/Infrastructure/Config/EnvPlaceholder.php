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
 * The `%env(VAR)%` / `%env(file:VAR)%` spelling a standalone configuration
 * uses to point at a credential, parsed once so the resolver that reads it and
 * the commands that report on it agree on what a value refers to.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EnvPlaceholder
{
    private const string PATTERN = '/^%env\(([^)]+)\)%$/';

    private const string FILE_PROCESSOR = 'file:';

    private function __construct(
        public string $variableName,
        public bool $readsFile,
    ) {}

    public static function in(string $value): ?self
    {
        if (1 !== preg_match(self::PATTERN, $value, $matches)) {
            return null;
        }

        $expression = $matches[1];

        return str_starts_with($expression, self::FILE_PROCESSOR)
            ? new self(substr($expression, \strlen(self::FILE_PROCESSOR)), true)
            : new self($expression, false);
    }
}
