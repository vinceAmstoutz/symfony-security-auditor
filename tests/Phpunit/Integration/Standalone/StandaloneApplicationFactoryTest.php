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
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($application->has('audit:run'));
        self::assertTrue($application->has('audit'));
    }

    #[RunInSeparateProcess]
    public function test_the_registered_audit_command_keeps_the_full_cli_option_surface(): void
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        $inputDefinition = $application->find('audit:run')->getDefinition();
        $optionNames = array_keys($inputDefinition->getOptions());

        self::assertSame([], array_diff(
            ['format', 'output', 'dry-run', 'no-cache', 'path', 'since', 'baseline', 'generate-baseline', 'fail-on'],
            $optionNames,
        ));
    }
}
