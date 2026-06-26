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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\DependencyInjection\Kernel\BundleInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BundleExtensionLoader
{
    /**
     * @param array<array-key, mixed> $config
     */
    public function load(BundleInterface $bundle, array $config, ContainerBuilder $containerBuilder): void
    {
        $extension = $bundle->getContainerExtension();
        if (!$extension instanceof ExtensionInterface) {
            throw MissingBundleExtensionException::forBundle($bundle::class);
        }

        $extension->load([$config], $containerBuilder);
    }
}
