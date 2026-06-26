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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\BundleExtensionLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone\Fixture\ExtensionlessBundle;

final class BundleExtensionLoaderTest extends TestCase
{
    public function test_it_loads_a_bundle_extension_into_the_container(): void
    {
        $containerBuilder = new ContainerBuilder(new ParameterBag([
            'kernel.cache_dir' => sys_get_temp_dir(),
            'kernel.build_dir' => sys_get_temp_dir(),
            'kernel.project_dir' => sys_get_temp_dir(),
            'kernel.environment' => 'prod',
            'kernel.debug' => false,
        ]));

        (new BundleExtensionLoader())->load(new SymfonySecurityAuditorBundle(), [], $containerBuilder);

        self::assertTrue($containerBuilder->hasDefinition(AuditCommand::class));
    }

    public function test_it_rejects_a_bundle_without_a_container_extension(): void
    {
        $this->expectException(MissingBundleExtensionException::class);

        (new BundleExtensionLoader())->load(new ExtensionlessBundle(), [], new ContainerBuilder());
    }
}
