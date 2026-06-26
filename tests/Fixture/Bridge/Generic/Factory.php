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

/*
 * Test fixture mirroring a pick-and-fetched symfony/ai-generic-platform bridge:
 * the classes exist on the classmap but the package is absent from Composer's
 * InstalledVersions, exactly the runtime shape ContainerBuilder::willBeAvailable expects.
 * Lives in the bridge namespace on purpose; that package is never a Composer dependency
 * here, so there is no FQCN clash.
 */

namespace Symfony\AI\Platform\Bridge\Generic;

use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Test\InMemoryPlatform;

final class Factory
{
    public static function createPlatform(): PlatformInterface
    {
        return new InMemoryPlatform('stub-response');
    }
}
