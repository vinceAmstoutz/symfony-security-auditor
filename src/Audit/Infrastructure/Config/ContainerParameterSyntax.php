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

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * A value written into the standalone config reaches the container verbatim,
 * where `ParameterBag` reads `%name%` as a parameter reference and `%%` as an
 * escaped percent. Neither is what someone typing a URL means: the first aborts
 * the run with "You have requested a non-existent parameter", the second
 * silently rewrites the value. A whole-value `%env(VAR)%` is the exception,
 * because `StandalonePlatformConfigResolver` resolves it before the container
 * is built, escaping what it substitutes so a secret is never read as syntax.
 * A URL `init` writes is escaped the same way, so its percent-encoded octets
 * (`%2F`) reach the container as typed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ContainerParameterSyntax
{
    private const string REFERENCE_PATTERN = '/%%|%[^%\s]++%/';

    private const string ESCAPE_OR_REFERENCE_PATTERN = '/%%|%([^%\s]++)%/';

    private const string ENV_REFERENCE_NAME = '/^env\(.+\)$/';

    private const string PERCENT_NOT_STARTING_AN_OCTET = '/%(?![0-9A-Fa-f]{2})/';

    private const string ENV_PLACEHOLDER_PREFIX = '/env_[0-9a-f]{16}_/i';

    public static function escape(string $literal): string
    {
        return str_replace('%', '%%', $literal);
    }

    public static function unescape(string $value): string
    {
        return str_replace('%%', '%', $value);
    }

    public static function isAbsentFrom(string $value): bool
    {
        return EnvPlaceholder::in($value) instanceof EnvPlaceholder
            || !self::holdsReference($value);
    }

    /**
     * Whether the container would read part of the value as syntax — a
     * `%name%` or `%env(VAR)%` reference, or an escaped `%%` — whatever the
     * resolver makes of a whole-value placeholder first.
     */
    public static function holdsReference(string $value): bool
    {
        return 1 === preg_match(self::REFERENCE_PATTERN, $value);
    }

    /**
     * Whether the value spells the placeholder the container writes for an
     * `%env()%` it has already read, which it swaps for the variable wherever
     * the text appears, whatever the case.
     */
    public static function holdsEnvPlaceholder(string $value): bool
    {
        return 1 === preg_match(self::ENV_PLACEHOLDER_PREFIX, $value);
    }

    /**
     * A URL holds a `%` only to percent-encode an octet, which `literal()`
     * carries to the container intact; a `%` that starts none — the closing
     * one of `%BASE_URL%`, even when the name itself opens with two hex digits
     * — belongs to a reference the user meant, which escaping would silently
     * turn into text, or to no valid URL at all. A whole-value `%env()%` is
     * the caller's to accept before asking.
     */
    public static function isAbsentFromUrl(string $url): bool
    {
        return 1 !== preg_match(self::PERCENT_NOT_STARTING_AN_OCTET, $url);
    }

    /**
     * Text that happens to hold a `%…%` pair — a regex such as
     * `/sprintf\(.*%s.*%d/`, a range such as `50%-60%` — must reach the
     * setting as typed, while a reference the container can resolve
     * (`%env(VAR)%`, `%kernel.project_dir%`) and a doubled `%%` keep their
     * meaning. A pair naming a parameter the bag lacks would abort the run
     * with "non-existent parameter", so it is escaped to the text it was.
     */
    public static function escapeUnresolvable(string $value, ParameterBagInterface $parameterBag): string
    {
        return preg_replace_callback(
            self::ESCAPE_OR_REFERENCE_PATTERN,
            static fn (array $match): string => \array_key_exists(1, $match) && !self::isResolvable($match[1], $parameterBag) ? self::escape($match[0]) : $match[0],
            $value,
        ) ?? $value;
    }

    /**
     * The spelling the container reads back as `$value`: a whole-value
     * `%env(VAR)%` stays a placeholder for the resolver to substitute, and
     * anything else has every `%` doubled.
     */
    public static function literal(string $value): string
    {
        return EnvPlaceholder::in($value) instanceof EnvPlaceholder ? $value : self::escape($value);
    }

    private static function isResolvable(string $name, ParameterBagInterface $parameterBag): bool
    {
        return 1 === preg_match(self::ENV_REFERENCE_NAME, $name) || $parameterBag->has($name);
    }
}
