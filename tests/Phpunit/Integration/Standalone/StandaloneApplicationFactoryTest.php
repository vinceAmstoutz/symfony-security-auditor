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

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;

final class StandaloneApplicationFactoryTest extends TestCase
{
    private string $configHome;

    private string $cacheHome;

    #[Override]
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

    #[Override]
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

    public function test_it_registers_the_audit_command_without_reading_a_config_file(): void
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($application->has('audit:run'));
    }

    public function test_it_reports_the_installed_package_version_instead_of_unknown(): void
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertSame((new ReportPackage())->version(), $application->getVersion());
    }

    public function test_it_registers_the_init_command(): void
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($application->has('init'));
    }

    public function test_it_registers_the_self_update_command(): void
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ], '/usr/local/bin/symfony-security-auditor')->create();

        self::assertTrue($application->has('self-update'));
    }

    public function test_it_registers_the_audit_command_as_visible(): void
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertFalse($application->get('audit:run')->isHidden());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_resolves_the_bridge_autoload_file_under_the_data_directory(): void
    {
        self::assertSame(
            '/xdg/data/symfony-security-auditor/vendor/autoload.php',
            StandaloneApplicationFactory::bridgeAutoloadFile(['XDG_DATA_HOME' => '/xdg/data']),
        );
    }

    public function test_it_resolves_the_project_config_file_under_the_working_directory(): void
    {
        self::assertSame(
            '/work/project/.symfony-security-auditor.yaml',
            StandaloneApplicationFactory::projectConfigFile(['PWD' => '/work/project']),
        );
    }

    public function test_it_falls_back_to_the_process_working_directory_when_pwd_is_not_exported(): void
    {
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);

        self::assertSame(
            \sprintf('%s/.symfony-security-auditor.yaml', $workingDirectory),
            StandaloneApplicationFactory::projectConfigFile([]),
        );
    }

    public function test_it_falls_back_to_the_process_working_directory_when_pwd_is_exported_empty(): void
    {
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);

        self::assertSame(
            \sprintf('%s/.symfony-security-auditor.yaml', $workingDirectory),
            StandaloneApplicationFactory::projectConfigFile(['PWD' => '']),
        );
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
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
