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

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

// Not readonly: PhpFileLoader carries the mutable loader state this exposes.
/**
 * Exposes the `ContainerConfigurator` a `PhpFileLoader` builds for itself, so a
 * non-bundle host can call the composition root with the same loader-bound
 * `instanceof` conditionals Symfony's own extension loading uses.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class CompositionRootLoader extends PhpFileLoader
{
    public function containerConfigurator(string $path): ContainerConfigurator
    {
        return new ContainerConfigurator($this->container, $this, $this->instanceof, $path, $path, $this->env);
    }
}
