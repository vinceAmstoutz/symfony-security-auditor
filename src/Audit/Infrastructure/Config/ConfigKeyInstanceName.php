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
 * An instance name as `symfony/config` will store it. `ArrayNode::preNormalize()`
 * rewrites a key holding a hyphen and no underscore, and an instance is a
 * prototyped key like any other, so `generic.my-gateway` registers the service
 * under `my_gateway`. Writing the name the user typed into `provider:` would
 * then point at a service that does not exist, so the name is folded here the
 * same way the framework will fold it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConfigKeyInstanceName
{
    private const string PLATFORM_NODE = 'platform';

    private const string PLATFORM_PLACEHOLDER = 'a_platform';

    public static function of(string $instance): string
    {
        if (!str_contains($instance, '-') || str_contains($instance, '_')) {
            return $instance;
        }

        return str_replace('-', '_', $instance);
    }

    /**
     * A name only works if the config file still holds it after `init` writes
     * it, so the same dumper and parser that will handle the file are asked
     * about a block nested the way the writer nests one: `0` is dumped as a
     * sequence entry the prototype cannot take a name from, `.inf` and `.nan`
     * are dumped unquoted and refused on the way back in, and a name read as a
     * YAML tag or as the merge key comes back as something else entirely, which
     * would leave `provider:` pointing at an instance the block does not hold.
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
     * The instance level is keyed by `array-key` rather than by `string`
     * because PHP stores `'0'` as the integer key that makes the block a list.
     *
     * @return array<string, array<string, array<array-key, array<never, never>>>>
     */
    private static function nestedTheWayItIsWritten(string $key): array
    {
        return [self::PLATFORM_NODE => [self::PLATFORM_PLACEHOLDER => [$key => []]]];
    }
}
