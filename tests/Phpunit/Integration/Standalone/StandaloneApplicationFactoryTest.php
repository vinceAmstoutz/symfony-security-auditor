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
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\LazyCommand;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\StaleBridgeTreeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ModelsDevCatalogRefresher;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\NullPricingCatalogRefresher;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServeCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;

final class StandaloneApplicationFactoryTest extends TestCase
{
    private const string BUNDLED_RELEASE = 'v0.14.1';

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

    #[DataProvider('credentialCommandNames')]
    public function test_it_registers_the_credential_commands(string $commandName): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertTrue($standaloneApplication->has($commandName));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function credentialCommandNames(): iterable
    {
        yield 'set' => ['auth:set'];
        yield 'status' => ['auth:status'];
        yield 'remove' => ['auth:remove'];
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

    public function test_it_exposes_one_pending_binary_swap_for_the_entry_point_to_commit(): void
    {
        $standaloneApplicationFactory = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ]);

        self::assertSame($standaloneApplicationFactory->pendingBinarySwap(), $standaloneApplicationFactory->pendingBinarySwap());
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

    public function test_pricing_catalog_refresher_is_null_when_offline_only_is_spelled_with_a_hyphen(): void
    {
        $xdgConfigPathResolver = $this->resolverForConfig("privacy:\n    offline-only: true\n");

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

    private function applicationTesterWithoutConfiguration(): ApplicationTester
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
            'SSA_NO_UPDATE_CHECK' => '1',
        ])->create();
        $standaloneApplication->setAutoExit(false);

        return new ApplicationTester($standaloneApplication);
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

    public function test_it_registers_the_mcp_server_command_as_visible_without_reading_a_config_file(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertFalse($standaloneApplication->get('mcp:serve')->isHidden());
    }

    public function test_it_registers_the_audit_command_as_visible(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        self::assertFalse($standaloneApplication->get('audit:run')->isHidden());
    }

    public function test_it_loads_the_bridge_tree_under_the_data_directory(): void
    {
        $dataHome = $this->bridgeTreeHome("touch(__DIR__.'/loaded');", self::BUNDLED_RELEASE);

        $warning = StandaloneApplicationFactory::loadBridgeTree(['XDG_DATA_HOME' => $dataHome], self::BUNDLED_RELEASE);

        self::assertSame([null, true], [$warning, is_file($dataHome.'/symfony-security-auditor/vendor/loaded')]);
    }

    public function test_it_leaves_a_bridge_tree_built_for_another_ai_platform_release_unloaded(): void
    {
        $dataHome = $this->bridgeTreeHome("touch(__DIR__.'/loaded');", 'v0.12.0');

        $warning = StandaloneApplicationFactory::loadBridgeTree(['XDG_DATA_HOME' => $dataHome], self::BUNDLED_RELEASE);

        self::assertSame([null, false], [$warning, is_file($dataHome.'/symfony-security-auditor/vendor/loaded')]);
    }

    public function test_it_names_the_data_directory_of_a_bridge_tree_it_cannot_load(): void
    {
        $dataHome = $this->bridgeTreeHome("throw new RuntimeException('Composer detected issues in your platform.');", self::BUNDLED_RELEASE);

        self::assertStringStartsWith(
            \sprintf('The provider bridge under "%s/symfony-security-auditor" cannot be loaded by this binary: Composer detected issues in your platform.', $dataHome),
            (string) StandaloneApplicationFactory::loadBridgeTree(['XDG_DATA_HOME' => $dataHome], self::BUNDLED_RELEASE),
        );
    }

    public function test_the_audit_command_reads_the_config_that_ships_with_the_project_it_names(): void
    {
        $projectDirectory = $this->configHome.'/audited';
        (new Filesystem())->dumpFile($projectDirectory.'/.symfony-security-auditor.yaml', "model: [unclosed\n");
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
            'SSA_NO_UPDATE_CHECK' => '1',
        ])->create();
        $standaloneApplication->setAutoExit(false);

        $applicationTester = new ApplicationTester($standaloneApplication);

        $statusCode = $applicationTester->run(['command' => AuditCommand::ALIAS, 'project-path' => $projectDirectory]);

        self::assertSame(
            [Command::FAILURE, true],
            [$statusCode, str_contains((string) preg_replace('/\s+/', '', $applicationTester->getDisplay()), $projectDirectory.'/.symfony-security-auditor.yaml')],
            $applicationTester->getDisplay(),
        );
    }

    public function test_there_is_no_bridge_tree_to_load_without_a_data_directory(): void
    {
        self::assertNull(StandaloneApplicationFactory::loadBridgeTree([], self::BUNDLED_RELEASE));
    }

    #[DataProvider('commandsNeedingTheBridgeTree')]
    public function test_a_command_needing_a_bridge_tree_built_for_another_ai_platform_release_says_how_to_rebuild_it(string $commandName): void
    {
        $dataHome = $this->bridgeTreeHome('', 'v0.12.0');
        $this->writeConfig("provider: ollama\nplatform:\n    ollama:\n        endpoint: 'http://localhost:11434'\nmodel: llama3.2\n");
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, $this->cacheHome, null, $dataHome);
        $lazyCommand = (new StandaloneApplicationFactory(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver([])),
            $xdgConfigPathResolver,
            self::createStub(BridgeInstallerInterface::class),
            bundledAiPlatformVersion: self::BUNDLED_RELEASE,
        ))->create()->find($commandName);
        self::assertInstanceOf(LazyCommand::class, $lazyCommand);

        $this->expectException(StaleBridgeTreeException::class);
        $this->expectExceptionMessageMatches('/symfony\/ai-platform v0\.12\.0, but this binary bundles v0\.14\.1: .* "symfony-security-auditor init --provider=ollama --force"/');

        $lazyCommand->getCommand();
    }

    public function test_doctor_fails_on_a_bridge_tree_built_for_another_ai_platform_release(): void
    {
        $dataHome = $this->bridgeTreeHome('', 'v0.12.0');
        $this->writeConfig("provider: ollama\nplatform:\n    ollama:\n        endpoint: 'http://localhost:11434'\nmodel: llama3.2\n");
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, $this->cacheHome, null, $dataHome);
        $standaloneApplication = (new StandaloneApplicationFactory(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver([])),
            $xdgConfigPathResolver,
            self::createStub(BridgeInstallerInterface::class),
            bundledAiPlatformVersion: self::BUNDLED_RELEASE,
        ))->create();
        $standaloneApplication->setAutoExit(false);

        $applicationTester = new ApplicationTester($standaloneApplication);

        $statusCode = $applicationTester->run(['command' => 'doctor']);

        self::assertSame(
            [Command::FAILURE, true],
            [$statusCode, str_contains((string) preg_replace('/\s+/', ' ', $applicationTester->getDisplay()), 'was installed for symfony/ai-platform v0.12.0, but this binary bundles v0.14.1')],
            $applicationTester->getDisplay(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function commandsNeedingTheBridgeTree(): iterable
    {
        yield 'audit' => [AuditCommand::ALIAS];
        yield 'mcp:serve' => [McpServeCommand::NAME];
    }

    private function bridgeTreeHome(string $autoloaderBody, string $aiPlatformRelease): string
    {
        $dataHome = $this->cacheHome.'/data';
        $filesystem = new Filesystem();
        $filesystem->dumpFile($dataHome.'/symfony-security-auditor/vendor/autoload.php', \sprintf("<?php\n\n%s\n", $autoloaderBody));
        $filesystem->dumpFile(
            $dataHome.'/symfony-security-auditor/vendor/composer/installed.php',
            \sprintf("<?php return %s;\n", var_export(['versions' => ['symfony/ai-platform' => ['pretty_version' => $aiPlatformRelease]]], true)),
        );

        return $dataHome;
    }

    public function test_it_keeps_the_shells_spelling_of_the_working_directory_when_pwd_names_it(): void
    {
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);
        $shellSpelling = sys_get_temp_dir().'/ssa_pwd_'.bin2hex(random_bytes(6));
        symlink($workingDirectory, $shellSpelling);

        try {
            self::assertSame(
                $shellSpelling.'/.symfony-security-auditor.yaml',
                StandaloneApplicationFactory::projectConfigFile(['PWD' => $shellSpelling]),
            );
        } finally {
            unlink($shellSpelling);
        }
    }

    public function test_it_ignores_a_pwd_naming_another_existing_directory(): void
    {
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);
        self::assertNotSame(realpath(sys_get_temp_dir()), realpath($workingDirectory));

        self::assertSame(
            \sprintf('%s/.symfony-security-auditor.yaml', $workingDirectory),
            StandaloneApplicationFactory::projectConfigFile(['PWD' => sys_get_temp_dir()]),
        );
    }

    public function test_it_ignores_a_pwd_inherited_from_another_directory(): void
    {
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);

        self::assertSame(
            \sprintf('%s/.symfony-security-auditor.yaml', $workingDirectory),
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

    /**
     * @param array<string, mixed> $input
     */
    #[DataProvider('describingInvocations')]
    public function test_it_describes_the_container_built_commands_before_any_configuration_exists(array $input, string $expected): void
    {
        $applicationTester = $this->applicationTesterWithoutConfiguration();

        $statusCode = $applicationTester->run($input);

        self::assertSame(
            [Command::SUCCESS, true],
            [$statusCode, str_contains((string) preg_replace('/\s+/', ' ', $applicationTester->getDisplay()), $expected)],
            $applicationTester->getDisplay(),
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function describingInvocations(): iterable
    {
        yield 'mcp:serve --help' => [['command' => McpServeCommand::NAME, '--help' => true], McpServeCommand::DESCRIPTION];
        yield 'mcp:serve -h' => [['command' => McpServeCommand::NAME, '-h' => true], McpServeCommand::DESCRIPTION];
        yield 'help mcp:serve' => [['command' => 'help', 'command_name' => McpServeCommand::NAME], McpServeCommand::DESCRIPTION];
        yield 'audit --help' => [['command' => AuditCommand::ALIAS, '--help' => true], '--dry-run'];
        yield 'help audit' => [['command' => 'help', 'command_name' => AuditCommand::ALIAS], 'runs a multi-agent LLM security audit against a Symfony project'];
        yield 'list --format=json' => [['command' => 'list', '--format' => 'json'], '"name":"mcp:serve"'];
        yield 'an abbreviated help audit' => [['command' => 'hel', 'command_name' => AuditCommand::ALIAS], 'runs a multi-agent LLM security audit against a Symfony project'];
        yield 'an abbreviated list --format=json' => [['command' => 'li', '--format' => 'json'], '"name":"mcp:serve"'];
        yield 'an abbreviated list in capitals' => [['command' => 'LI', '--format' => 'json'], '"name":"mcp:serve"'];
        yield 'the default command as json' => [['--format' => 'json'], '"name":"audit:run"'];
        yield 'shell completion of an audit option' => [['command' => '_complete', '--shell' => 'bash', '--api-version' => '1', '--current' => '2', '--input' => ['symfony-security-auditor', AuditCommand::ALIAS, '--dry']], '--dry-run'];
    }

    public function test_no_other_command_answers_to_an_abbreviation_of_help_or_list(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
            'SSA_NO_UPDATE_CHECK' => '1',
        ])->create();

        $abbreviating = array_values(array_filter(
            array_keys($standaloneApplication->all()),
            static fn (string $name): bool => str_starts_with('help', strtolower($name)) || str_starts_with('list', strtolower($name)),
        ));
        sort($abbreviating);

        self::assertSame(['help', 'list'], $abbreviating);
    }

    public function test_an_audit_whose_path_merely_looks_like_the_help_flag_still_needs_a_configuration(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => sys_get_temp_dir().'/ssa-absent-'.bin2hex(random_bytes(6)),
            'XDG_CACHE_HOME' => $this->cacheHome,
            'SSA_NO_UPDATE_CHECK' => '1',
        ])->create();
        $standaloneApplication->setAutoExit(false);

        $bufferedOutput = new BufferedOutput();

        $standaloneApplication->run(new StringInput(\sprintf('%s -- --help', AuditCommand::ALIAS)), $bufferedOutput);

        self::assertStringContainsString('No LLM platform configured', $bufferedOutput->fetch());
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
