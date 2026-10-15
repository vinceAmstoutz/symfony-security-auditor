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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat;

use Symfony\AI\Platform\Bridge\Generic\Factory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\GenericPlatformFactory;

/**
 * Loads this suite on top of any checkout's Composer autoloader — the tree
 * under test when replaying, an older release when recording — and routes
 * the generic platform bridge to the scripted provider. Both loaders are
 * prepended so they win over the checkout's own classmap.
 */
final class CompatAutoloader
{
    private const string NAMESPACE_PREFIX = 'VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\\';

    private const string GENERIC_BRIDGE_FACTORY = Factory::class;

    private static bool $registered = false;

    public static function register(): void
    {
        if (self::$registered) {
            return;
        }

        self::$registered = true;
        spl_autoload_register(self::loadSuiteClass(...), true, true);
        spl_autoload_register(self::aliasGenericBridge(...), true, true);
    }

    private static function loadSuiteClass(string $class): void
    {
        if (!str_starts_with($class, self::NAMESPACE_PREFIX)) {
            return;
        }

        $file = \sprintf('%s/%s.php', __DIR__, str_replace('\\', '/', substr($class, \strlen(self::NAMESPACE_PREFIX))));
        if (is_file($file)) {
            require_once $file;
        }
    }

    private static function aliasGenericBridge(string $class): void
    {
        if (self::GENERIC_BRIDGE_FACTORY === $class) {
            class_alias(GenericPlatformFactory::class, $class);
        }
    }
}
