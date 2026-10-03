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
 * The shape a name must have for a `%env(NAME)%` placeholder, a shell export
 * and a credential-store entry to all refer to the same variable.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EnvironmentVariableName
{
    private const string PATTERN = '/^[A-Za-z_]\w*$/D';

    /**
     * A value longer than this is more likely the API key itself, pasted into
     * the wrong option, than a mistyped name: it is masked rather than echoed
     * into a terminal or a CI log.
     */
    private const int LONGEST_NAME_SHOWN = 23;

    private const string CONTROL_AND_NON_ASCII_BYTES = "\0..\37\177..\377";

    public static function isValid(string $name): bool
    {
        return 1 === preg_match(self::PATTERN, $name);
    }

    public static function violationFor(string $name): ?string
    {
        return self::isValid($name)
            ? null
            : \sprintf('"%s" is not a valid environment variable name (letters, digits, and underscores only; must not start with a digit).', self::shown($name));
    }

    /**
     * How a refused name is quoted back: as typed with control bytes escaped,
     * or masked when it is long enough to be a key.
     */
    public static function shown(string $name): string
    {
        return \strlen($name) <= self::LONGEST_NAME_SHOWN
            ? addcslashes($name, self::CONTROL_AND_NON_ASCII_BYTES)
            : CredentialIdentity::of($name)->maskedPreview;
    }
}
