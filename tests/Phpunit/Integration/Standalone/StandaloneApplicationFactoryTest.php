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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ModelsDevCatalogRefresher;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\NullPricingCatalogRefresher;
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
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($standaloneApplication->has('audit:run'));
        self::assertTrue($standaloneApplication->has('audit'));
    }

    public function test_it_registers_the_audit_command_without_reading_a_config_file(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($standaloneApplication->has('audit:run'));
    }

    public function test_it_reports_the_installed_package_version_instead_of_unknown(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertSame((new ReportPackage())->version(), $standaloneApplication->getVersion());
    }

    public function test_it_includes_the_bundled_models_dev_version_in_the_long_version(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertStringContainsString(
            \sprintf('symfony/models-dev %s', (new ReportPackage('symfony/models-dev'))->version()),
            $standaloneApplication->getLongVersion(),
        );
    }

    public function test_it_registers_the_init_command(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($standaloneApplication->has('init'));
    }

    public function test_it_registers_the_self_update_command(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ], '/usr/local/bin/symfony-security-auditor')->create();

        self::assertTrue($standaloneApplication->has('self-update'));
    }

    public function test_it_builds_the_application_when_no_cache_directory_can_be_resolved(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([])->create();

        self::assertTrue($standaloneApplication->has('doctor'), 'an environment with no HOME and no XDG variables leaves the refreshed-catalog location unresolvable, which must not stop the application from building');
    }

    public function test_it_registers_the_doctor_command(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($standaloneApplication->has('doctor'));
    }

    public function test_it_builds_the_application_when_update_checks_are_disabled(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
            'SSA_NO_UPDATE_CHECK' => '1',
        ])->create();

        self::assertTrue($standaloneApplication->has('audit:run'));
    }

    /**
     * @param array<string, string> $environment
     */
    #[DataProvider('updateCheckOptOutCases')]
    public function test_it_reports_whether_update_checks_are_disabled(array $environment, bool $expected): void
    {
        self::assertSame($expected, StandaloneApplicationFactory::updateChecksDisabled($environment));
    }

    /**
     * @return iterable<string, array{array<string, string>, bool}>
     */
    public static function updateCheckOptOutCases(): iterable
    {
        yield 'opt-out variable set' => [['SSA_NO_UPDATE_CHECK' => '1'], true];
        yield 'opt-out variable absent' => [[], false];
        yield 'opt-out variable empty' => [['SSA_NO_UPDATE_CHECK' => ''], false];
        yield 'opt-out variable explicitly zero' => [['SSA_NO_UPDATE_CHECK' => '0'], false];
        yield 'opt-out variable set to an arbitrary value' => [['SSA_NO_UPDATE_CHECK' => 'true'], true];
    }

    public function test_pricing_catalog_refresher_downloads_when_no_config_file_exists_yet(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)), $this->cacheHome, null);

        self::assertInstanceOf(
            ModelsDevCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    public function test_pricing_catalog_refresher_downloads_when_the_config_file_holds_no_mapping(): void
    {
        $xdgConfigPathResolver = $this->resolverForConfig('');

        self::assertInstanceOf(
            ModelsDevCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    public function test_pricing_catalog_refresher_downloads_when_the_privacy_key_has_no_offline_only_entry(): void
    {
        $xdgConfigPathResolver = $this->resolverForConfig("privacy:\n    secret_scrubbing:\n        enabled: true\n");

        self::assertInstanceOf(
            ModelsDevCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    public function test_pricing_catalog_refresher_downloads_when_the_config_file_explicitly_disables_offline_only(): void
    {
        $xdgConfigPathResolver = $this->resolverForConfig("privacy:\n    offline_only: false\n");

        self::assertInstanceOf(
            ModelsDevCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    public function test_pricing_catalog_refresher_fails_closed_when_the_config_file_is_malformed(): void
    {
        $xdgConfigPathResolver = $this->resolverForConfig("platform: [a, b\n");

        self::assertInstanceOf(
            NullPricingCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    public function test_pricing_catalog_refresher_fails_closed_when_the_home_directory_is_unresolvable(): void
    {
        self::assertInstanceOf(
            NullPricingCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher(new XdgConfigPathResolver(null, null, null)),
        );
    }

    public function test_pricing_catalog_refresher_is_null_when_offline_only_is_enabled(): void
    {
        $xdgConfigPathResolver = $this->resolverForConfig("privacy:\n    offline_only: true\n");

        self::assertInstanceOf(
            NullPricingCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    public function test_pricing_catalog_refresher_downloads_when_offline_only_is_disabled(): void
    {
        $xdgConfigPathResolver = $this->resolverForConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");

        self::assertInstanceOf(
            ModelsDevCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    public function test_pricing_catalog_refresher_fails_closed_when_only_the_config_path_is_unresolvable(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, $this->cacheHome, null);

        self::assertInstanceOf(
            NullPricingCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
            'an unreadable config path must fail closed on its own, not rely on the cache path also being unresolvable',
        );
    }

    public function test_pricing_catalog_refresher_is_null_when_the_cache_directory_is_unresolvable(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);

        self::assertInstanceOf(
            NullPricingCatalogRefresher::class,
            StandaloneApplicationFactory::pricingCatalogRefresher($xdgConfigPathResolver),
        );
    }

    private function resolverForConfig(string $yaml): XdgConfigPathResolver
    {
        $this->writeConfig($yaml);

        return new XdgConfigPathResolver($this->configHome, $this->cacheHome, null);
    }

    private function writeConfig(string $yaml): void
    {
        (new Filesystem())->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }

    public function test_it_registers_the_audit_command_as_visible(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertFalse($standaloneApplication->get('audit:run')->isHidden());
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
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        $inputDefinition = $standaloneApplication->find('audit:run')->getDefinition();
        $optionNames = array_keys($inputDefinition->getOptions());

        self::assertSame([], array_diff(
            ['format', 'output', 'dry-run', 'no-cache', 'path', 'since', 'baseline', 'generate-baseline', 'fail-on', 'min-score'],
            $optionNames,
        ));
    }
}
