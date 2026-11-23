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
 * Tells and escapes the container's parameter syntax (`%name%`, `%%`) in a
 * value the standalone config hands the container, so a URL or a secret
 * reaches it as typed. A whole-value `%env(VAR)%` is resolved before the
 * container is built instead.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
     * True when the container would read part of the value as syntax: a
     * `%name%` or `%env(VAR)%` reference or a `%%`, whole-value placeholders
     * included.
     */
    public static function holdsReference(string $value): bool
    {
        return 1 === preg_match(self::REFERENCE_PATTERN, $value);
    }

    /**
     * True when the value spells, in any case, the placeholder the container
     * swaps for the variable of an `%env()%` it has read.
     */
    public static function holdsEnvPlaceholder(string $value): bool
    {
        return 1 === preg_match(self::ENV_PLACEHOLDER_PREFIX, $value);
    }

    /**
     * True when every `%` of the URL percent-encodes an octet, which
     * `literal()` carries to the container intact. A whole-value `%env()%`
     * is the caller's to accept first.
     */
    public static function isAbsentFromUrl(string $url): bool
    {
        return 1 !== preg_match(self::PERCENT_NOT_STARTING_AN_OCTET, $url);
    }

    /**
     * Escapes each `%…%` pair naming no parameter of the bag, so a regex such
     * as `/sprintf\(.*%s.*%d/` reaches the setting as typed. A resolvable
     * reference and a `%%` keep their meaning.
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
     * Returns the spelling the container reads back as `$value`: a
     * whole-value `%env(VAR)%` as it is, anything else with every `%` doubled.
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
