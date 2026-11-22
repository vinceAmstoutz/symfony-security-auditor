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

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * An instance name as `symfony/config` stores it: a name holding a hyphen and
 * no underscore has its hyphens turned into underscores, so `generic.my-gateway`
 * names the `my_gateway` service.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConfigKeyInstanceName
{
    private const string PLATFORM_NODE = 'zzz';

    private const string PLATFORM_PLACEHOLDER = 'a_platform';

    public static function of(string $instance): string
    {
        if (!str_contains($instance, '-') || str_contains($instance, '_')) {
            return $instance;
        }

        return str_replace('-', '_', $instance);
    }

    /**
     * True when the name reads back unchanged from the config file `init`
     * writes, through the YAML dumper and parser that handle it: `0`, `.inf`
     * or a YAML tag may not.
     */
    public static function isUsable(string $instance): bool
    {
        $written = self::nestedTheWayItIsWritten(self::of($instance));

        if (array_is_list($written[self::PLATFORM_NODE][self::PLATFORM_PLACEHOLDER])) {
            return false;
        }

        try {
            return Yaml::parse(Yaml::dump($written)) === $written;
        } catch (ParseException) {
            return false;
        }
    }

    /**
     * @return array<string, array<string, array<array-key, array<never, never>>>>
     */
    private static function nestedTheWayItIsWritten(string $key): array
    {
        return [self::PLATFORM_NODE => [self::PLATFORM_PLACEHOLDER => [$key => []]]];
    }
}
