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

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;

final class StandaloneApplicationFactoryTest extends TestCase
{
    private string $configHome;

    private string $cacheHome;

    protected function setUp(): void
    {
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-app-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-app-cache-'.$suffix;

        (new Filesystem())->dumpFile(
            $this->configHome.'/symfony-security-auditor/config.yaml',
            "platform:\n    generic:\n        default:\n            base_url: 'http://localhost'\n",
        );
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove([$this->configHome, $this->cacheHome]);
    }

    #[RunInSeparateProcess]
    public function test_it_builds_a_console_application_exposing_the_audit_command_and_alias(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, $this->cacheHome, null);
        $standaloneConfigLoader = new StandaloneConfigLoader(
            $xdgConfigPathResolver,
            new StandalonePlatformConfigResolver(),
        );

        $application = (new StandaloneApplicationFactory($standaloneConfigLoader, $xdgConfigPathResolver))->create();

        self::assertTrue($application->has('audit:run'));
        self::assertTrue($application->has('audit'));
    }
}
