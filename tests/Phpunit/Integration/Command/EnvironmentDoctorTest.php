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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\StaleBridgeTreeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPreflightInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ComposerAvailabilityCheckerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ComposerProbe;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckResult;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Command\EnvironmentDoctor;

final class EnvironmentDoctorTest extends TestCase
{
    private string $configHome;

    private string $cacheHome;

    private string $dataHome;

    #[Override]
    protected function setUp(): void
    {
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-doctor-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-doctor-cache-'.$suffix;
        $this->dataHome = sys_get_temp_dir().'/ssa-doctor-data-'.$suffix;
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove([$this->configHome, $this->cacheHome, $this->dataHome]);
    }

    public function test_it_reports_every_check_green_when_the_environment_is_ready(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test-0123456789abcdefghij'\nmodel: 'gpt-4'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertEquals([
            new DoctorCheckResult('Configuration', DoctorCheckStatus::Ok, 'Config resolves and an API key is available: sk-tes…ghij (SHA256:2e9cd0e8ecfb255a).'),
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Ok, 'Installed and the audit boots with it.'),
            new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.'),
        ], \array_slice($results, 0, 3));
    }

    public function test_it_reports_a_platform_that_needs_no_api_key(): void
    {
        $this->writeConfig("platform:\n    ollama:\n        host_url: 'http://localhost:11434'\nmodel: 'llama3'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertSame('Config resolves; the configured platform needs no API key.', $results[0]->detail);
    }

    public function test_it_reports_the_bundled_pricing_catalog_version(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\nmodel: 'gpt-4'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertSame('Pricing catalog', $results[3]->label);
        self::assertSame(DoctorCheckStatus::Ok, $results[3]->status);
        self::assertMatchesRegularExpression('/^symfony\/models-dev v?[0-9]+(\.[0-9]+)* \(.+models-dev\.json\)\.$/', $results[3]->detail);
    }

    public function test_it_reports_a_refreshed_catalog_instead_of_the_bundled_one(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $this->installBridge();
        $refreshed = $this->cacheHome.'/symfony-security-auditor/models-dev.json';
        (new Filesystem())->dumpFile($refreshed, '{"anthropic":{"models":{"claude-opus-5":{"cost":{"input":5,"output":25}}}}}');

        $xdgConfigPathResolver = $this->resolver();
        $composerAvailabilityChecker = self::createStub(ComposerAvailabilityCheckerInterface::class);
        $composerAvailabilityChecker->method('probe')->willReturn(ComposerProbe::available());

        $environmentDoctor = new EnvironmentDoctor(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver([])),
            $xdgConfigPathResolver,
            $composerAvailabilityChecker,
            self::createStub(AuditPreflightInterface::class),
            new ModelsDevPricingProvider(new NullLogger(), $refreshed),
        );

        $results = $environmentDoctor->diagnose();

        self::assertSame(DoctorCheckStatus::Ok, $results[3]->status);
        self::assertStringContainsString($refreshed, $results[3]->detail, 'doctor must name the refreshed catalog the run actually prices from, not the bundled one');
        self::assertDoesNotMatchRegularExpression(
            '/symfony\/models-dev v?[0-9]/',
            $results[3]->detail,
            'the bundled package version describes the packaged catalog only; stamping it onto a refreshed override asserts a version that file does not have',
        );
    }

    public function test_it_names_the_bundled_catalog_when_the_refreshed_one_is_unusable(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $this->installBridge();
        $refreshed = $this->cacheHome.'/symfony-security-auditor/models-dev.json';
        (new Filesystem())->dumpFile($refreshed, '{"anthropic":{}}');

        $xdgConfigPathResolver = $this->resolver();
        $composerAvailabilityChecker = self::createStub(ComposerAvailabilityCheckerInterface::class);
        $composerAvailabilityChecker->method('isAvailable')->willReturn(true);

        $environmentDoctor = new EnvironmentDoctor(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver([])),
            $xdgConfigPathResolver,
            $composerAvailabilityChecker,
            self::createStub(AuditPreflightInterface::class),
            new ModelsDevPricingProvider(new NullLogger(), $refreshed),
        );

        $results = $environmentDoctor->diagnose();

        self::assertSame(DoctorCheckStatus::Ok, $results[3]->status);
        self::assertStringNotContainsString($refreshed, $results[3]->detail, 'the run prices from the bundled catalog, so doctor must not name an override it ignores');
        self::assertMatchesRegularExpression('/^symfony\/models-dev v?[0-9]+(\.[0-9]+)* \(.+models-dev\.json\)\.$/', $results[3]->detail);
    }

    public function test_it_warns_when_the_pricing_catalog_package_is_not_installed(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\nmodel: 'gpt-4'\n");
        $this->installBridge();

        $xdgConfigPathResolver = $this->resolver();
        $composerAvailabilityChecker = self::createStub(ComposerAvailabilityCheckerInterface::class);
        $composerAvailabilityChecker->method('probe')->willReturn(ComposerProbe::available());
        $auditPreflight = self::createStub(AuditPreflightInterface::class);

        $environmentDoctor = new EnvironmentDoctor(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver([])),
            $xdgConfigPathResolver,
            $composerAvailabilityChecker,
            $auditPreflight,
            new ModelsDevPricingProvider(new NullLogger(), null, 'vinceamstoutz/definitely-not-installed'),
            'vinceamstoutz/definitely-not-installed',
        );

        $results = $environmentDoctor->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Pricing catalog', DoctorCheckStatus::Warning, 'vinceamstoutz/definitely-not-installed not found — cost figures will show $0.00.'),
            $results[3],
        );
    }

    public function test_it_fails_the_bridge_check_when_the_installed_bridge_cannot_boot_the_audit(): void
    {
        $this->writeConfig("provider: openai\nplatform:\n    openai:\n        api_key: 'sk-test'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true, 'The "openai" platform is not registered.')->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, 'Installed, but the audit cannot start with it: The "openai" platform is not registered.'),
            $results[1],
        );
    }

    public function test_it_reports_a_boot_failure_whose_message_is_not_valid_utf8(): void
    {
        $this->writeConfig("provider: openai\nplatform:\n    openai:\n        api_key: 'sk-test'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true, "boom in \xAF\xFE dir")->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, "Installed, but the audit cannot start with it: boom in \xAF\xFE dir"),
            $results[1],
        );
    }

    public function test_it_reports_a_boot_failure_without_a_message_in_plain_words(): void
    {
        $this->writeConfig("provider: openai\nplatform:\n    openai:\n        api_key: 'sk-test'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true, '   ')->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, 'Installed, but the audit cannot start with it (the boot failed without an error message).'),
            $results[1],
        );
    }

    public function test_it_reports_the_bridge_installed_without_a_boot_probe_when_the_configuration_check_fails(): void
    {
        $this->writeConfig("model: 'gpt-4'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true, 'would only repeat the configuration failure')->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Ok, 'Installed.'),
            $results[1],
        );
    }

    public function test_it_fails_the_configuration_check_when_no_provider_is_configured(): void
    {
        $this->writeConfig("model: 'gpt-4'\n");

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, 'No provider is configured — run "init".'),
            $results[0],
        );
    }

    public function test_it_fails_the_api_key_check_when_the_referenced_variable_is_unset(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: '%env(OPENAI_API_KEY)%'\n");

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('API key', DoctorCheckStatus::Failure, MissingEnvironmentVariableException::forName('OPENAI_API_KEY')->getMessage()),
            $results[0],
        );
    }

    public function test_it_requires_no_key_of_a_platform_the_provider_does_not_select(): void
    {
        $this->writeConfig("provider: generic.my_gateway\nplatform:\n    generic:\n        my_gateway:\n            base_url: 'https://gw.example'\n            api_key: '%env(GW_TOKEN)%'\n    openai:\n        api_key: '%env(OPENAI_API_KEY)%'\n");

        $results = $this->doctorWith($this->resolver(), ['GW_TOKEN' => 'gw-0123456789abcdefghijklmn'], true)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Configuration', DoctorCheckStatus::Ok, 'Config resolves and an API key is available: gw-012…klmn (SHA256:28c119d571da66f6).'),
            $results[0],
        );
    }

    public function test_it_reports_an_unset_variable_behind_a_plain_setting_under_configuration_not_api_key(): void
    {
        $this->writeConfig("provider: generic.my_gateway\nplatform:\n    generic:\n        my_gateway:\n            base_url: '%env(GATEWAY_URL)%'\n            api_key: '%env(GW_TOKEN)%'\n");

        $results = $this->doctorWith($this->resolver(), ['GW_TOKEN' => 'gw-token'], true)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, MissingEnvironmentVariableException::forSetting('GATEWAY_URL')->getMessage()),
            $results[0],
        );
    }

    public function test_it_fails_the_api_key_check_when_the_referenced_credential_file_cannot_be_read(): void
    {
        $missingCredentialFile = \sprintf('%s/absent-api-key', $this->configHome);
        $this->writeConfig("platform:\n    openai:\n        api_key: '%env(file:OPENAI_API_KEY_FILE)%'\n");

        $results = $this->doctorWith($this->resolver(), ['OPENAI_API_KEY_FILE' => $missingCredentialFile], true)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('API key', DoctorCheckStatus::Failure, UnreadableCredentialFileException::forVariable('OPENAI_API_KEY_FILE', $missingCredentialFile)->getMessage()),
            $results[0],
        );
    }

    public function test_it_fails_the_configuration_check_when_a_placeholder_applies_an_env_processor(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: '%env(trim:OPENAI_API_KEY)%'\n");

        $results = $this->doctorWith($this->resolver(), ['OPENAI_API_KEY' => 'sk-test'], true)->diagnose();

        self::assertSame('Configuration', $results[0]->label);
        self::assertSame(DoctorCheckStatus::Failure, $results[0]->status);
        self::assertStringContainsString('The placeholder "%env(trim:OPENAI_API_KEY)%" applies an env processor', $results[0]->detail);
    }

    public function test_it_fails_the_configuration_check_when_the_config_file_is_malformed(): void
    {
        $this->writeConfig("platform: [a, b\n");

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertSame('Configuration', $results[0]->label);
        self::assertSame(DoctorCheckStatus::Failure, $results[0]->status);
        self::assertStringContainsString('is not valid YAML', $results[0]->detail);
    }

    public function test_it_fails_the_configuration_check_when_the_audited_project_redefines_the_platform(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $projectConfigFile = $this->configHome.'/project/.symfony-security-auditor.yaml';
        (new Filesystem())->dumpFile($projectConfigFile, "platform:\n    openai:\n        base_url: 'https://attacker.example'\n");

        $results = $this->doctorWith($this->resolver(), [], true, projectConfigFile: $projectConfigFile)->diagnose();

        self::assertSame('Configuration', $results[0]->label);
        self::assertSame(DoctorCheckStatus::Failure, $results[0]->status);
        self::assertStringContainsString('must not be able to point your API credentials at another endpoint', $results[0]->detail);
    }

    public function test_it_fails_the_configuration_check_when_the_audited_project_declares_a_sarif_import_path(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $projectConfigFile = $this->configHome.'/project/.symfony-security-auditor.yaml';
        (new Filesystem())->dumpFile($projectConfigFile, "scan:\n    import_sarif:\n        - /etc/passwd\n");

        $results = $this->doctorWith($this->resolver(), [], true, projectConfigFile: $projectConfigFile)->diagnose();

        self::assertSame('Configuration', $results[0]->label);
        self::assertSame(DoctorCheckStatus::Failure, $results[0]->status);
        self::assertStringContainsString('must not be able to point the scanner at paths of its choosing', $results[0]->detail);
    }

    public function test_it_fails_the_configuration_check_when_the_audited_project_declares_a_user_only_key(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $projectConfigFile = $this->configHome.'/project/.symfony-security-auditor.yaml';
        (new Filesystem())->dumpFile($projectConfigFile, "privacy:\n    allow_external_llm: true\n");

        $results = $this->doctorWith($this->resolver(), [], true, projectConfigFile: $projectConfigFile)->diagnose();

        self::assertSame('Configuration', $results[0]->label);
        self::assertSame(DoctorCheckStatus::Failure, $results[0]->status);
        self::assertStringContainsString('privacy', $results[0]->detail);
        self::assertStringContainsString($projectConfigFile, $results[0]->detail);
    }

    public function test_it_fails_the_configuration_and_bridge_checks_when_the_home_directory_is_unresolvable(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, null);

        $results = $this->doctorWith($xdgConfigPathResolver, [], true)->diagnose();

        $expectedMessage = UnresolvableConfigPathException::missingHome()->getMessage();
        self::assertEquals(new DoctorCheckResult('Configuration', DoctorCheckStatus::Failure, $expectedMessage), $results[0]);
        self::assertEquals(new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, $expectedMessage), $results[1]);
    }

    public function test_it_fails_the_bridge_check_when_the_provider_bridge_is_not_installed(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, 'Not installed — run "init --provider=<platform>" to download it.'),
            $results[1],
        );
    }

    public function test_it_fails_the_bridge_check_when_the_bridge_tree_holds_another_ai_platform_release(): void
    {
        $this->writeConfig("provider: ollama\nplatform:\n    ollama:\n        endpoint: 'http://localhost:11434'\n");
        $this->installBridge('v0.12.0');

        $results = $this->doctorBundling('v0.14.1')->diagnose();

        self::assertEquals(
            new DoctorCheckResult(
                'Provider bridge',
                DoctorCheckStatus::Failure,
                \sprintf('Installed, but the audit cannot start with it: %s', StaleBridgeTreeException::forTree($this->dataHome.'/symfony-security-auditor', 'v0.12.0', 'v0.14.1', 'ollama')->getMessage()),
            ),
            $results[1],
        );
    }

    public function test_it_fails_the_bridge_check_on_a_bridge_tree_holding_another_release_even_while_the_configuration_does_not_resolve(): void
    {
        $this->writeConfig("provider: openai\nplatform:\n    openai:\n        api_key: '%env(OPENAI_API_KEY)%'\n");
        $this->installBridge('v0.13.0');

        $results = $this->doctorBundling('v0.14.1')->diagnose();

        self::assertSame(
            [DoctorCheckStatus::Failure, DoctorCheckStatus::Failure, true],
            [$results[0]->status, $results[1]->status, str_contains($results[1]->detail, 'init --provider=openai --force')],
        );
    }

    public function test_it_boots_the_audit_with_a_bridge_tree_holding_the_bundled_release(): void
    {
        $this->writeConfig("provider: ollama\nplatform:\n    ollama:\n        endpoint: 'http://localhost:11434'\n");
        $this->installBridge('v0.14.1');

        $results = $this->doctorBundling('v0.14.1')->diagnose();

        self::assertEquals(new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Ok, 'Installed and the audit boots with it.'), $results[1]);
    }

    public function test_it_warns_when_composer_is_not_available(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], false)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Composer', DoctorCheckStatus::Warning, 'Not usable (php: not found) — needed only to run "init" or switch providers, not to audit. "init" lists how to install it.'),
            $results[2],
        );
    }

    /**
     * @param array<string, string> $environment
     */
    private function doctorWith(XdgConfigPathResolver $xdgConfigPathResolver, array $environment, bool $composerAvailable, ?string $preflightFailure = null, ?string $projectConfigFile = null): EnvironmentDoctor
    {
        $composerAvailabilityChecker = self::createStub(ComposerAvailabilityCheckerInterface::class);
        $composerAvailabilityChecker->method('probe')->willReturn($composerAvailable ? ComposerProbe::available() : ComposerProbe::unavailable('php: not found'));

        $auditPreflight = self::createStub(AuditPreflightInterface::class);
        $auditPreflight->method('failureReason')->willReturn($preflightFailure);

        return new EnvironmentDoctor(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver($environment), $projectConfigFile),
            $xdgConfigPathResolver,
            $composerAvailabilityChecker,
            $auditPreflight,
            new ModelsDevPricingProvider(new NullLogger()),
        );
    }

    private function resolver(): XdgConfigPathResolver
    {
        return new XdgConfigPathResolver($this->configHome, $this->cacheHome, null, $this->dataHome);
    }

    private function writeConfig(string $yaml): void
    {
        (new Filesystem())->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }

    private function installBridge(?string $aiPlatformRelease = null): void
    {
        (new Filesystem())->dumpFile($this->dataHome.'/symfony-security-auditor/vendor/autoload.php', "<?php\n");

        if (null !== $aiPlatformRelease) {
            (new Filesystem())->dumpFile(
                $this->dataHome.'/symfony-security-auditor/vendor/composer/installed.php',
                \sprintf("<?php return %s;\n", var_export(['versions' => ['symfony/ai-platform' => ['pretty_version' => $aiPlatformRelease]]], true)),
            );
        }
    }

    private function doctorBundling(string $bundledAiPlatformVersion): EnvironmentDoctor
    {
        $xdgConfigPathResolver = $this->resolver();
        $composerAvailabilityChecker = self::createStub(ComposerAvailabilityCheckerInterface::class);
        $composerAvailabilityChecker->method('probe')->willReturn(ComposerProbe::available());

        return new EnvironmentDoctor(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver([])),
            $xdgConfigPathResolver,
            $composerAvailabilityChecker,
            self::createStub(AuditPreflightInterface::class),
            new ModelsDevPricingProvider(new NullLogger()),
            bundledAiPlatformVersion: $bundledAiPlatformVersion,
        );
    }
}
