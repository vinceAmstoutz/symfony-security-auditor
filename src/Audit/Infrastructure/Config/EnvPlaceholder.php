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
 * The `%env(VAR)%` or `%env(file:VAR)%` placeholder a standalone
 * configuration points at a credential with.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class EnvPlaceholder
{
    private const string PATTERN = '/^%env\(([^)]+)\)%$/D';

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
