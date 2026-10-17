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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform;

use Symfony\AI\Platform\PlatformInterface;

/**
 * Stands in for the `symfony/ai-generic-platform` factory the standalone
 * binary's `platform: generic` block builds its platform with, so a standalone
 * scenario talks to the scripted provider instead of the network.
 */
final readonly class GenericPlatformFactory
{
    public static function createPlatform(): PlatformInterface
    {
        return new CompatPlatform();
    }
}
