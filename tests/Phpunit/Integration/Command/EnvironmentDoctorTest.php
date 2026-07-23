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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPreflightInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ComposerAvailabilityCheckerInterface;
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
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\nmodel: 'gpt-4'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertEquals([
            new DoctorCheckResult('Configuration', DoctorCheckStatus::Ok, 'Config resolves and the API-key variable is set.'),
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Ok, 'Installed and the audit boots with it.'),
            new DoctorCheckResult('Composer', DoctorCheckStatus::Ok, 'Available.'),
        ], $results);
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

    public function test_it_fails_the_configuration_check_when_the_config_file_is_malformed(): void
    {
        $this->writeConfig("platform: [a, b\n");

        $results = $this->doctorWith($this->resolver(), [], true)->diagnose();

        self::assertSame('Configuration', $results[0]->label);
        self::assertSame(DoctorCheckStatus::Failure, $results[0]->status);
        self::assertStringContainsString('is not valid YAML', $results[0]->detail);
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
            new DoctorCheckResult('Provider bridge', DoctorCheckStatus::Failure, 'Not installed — run "init" to download it.'),
            $results[1],
        );
    }

    public function test_it_warns_when_composer_is_not_available(): void
    {
        $this->writeConfig("platform:\n    openai:\n        api_key: 'sk-test'\n");
        $this->installBridge();

        $results = $this->doctorWith($this->resolver(), [], false)->diagnose();

        self::assertEquals(
            new DoctorCheckResult('Composer', DoctorCheckStatus::Warning, 'Not found — needed only to run "init" or switch providers, not to audit.'),
            $results[2],
        );
    }

    /**
     * @param array<string, string> $environment
     */
    private function doctorWith(XdgConfigPathResolver $xdgConfigPathResolver, array $environment, bool $composerAvailable, ?string $preflightFailure = null): EnvironmentDoctor
    {
        $composerAvailabilityChecker = self::createStub(ComposerAvailabilityCheckerInterface::class);
        $composerAvailabilityChecker->method('isAvailable')->willReturn($composerAvailable);

        $auditPreflight = self::createStub(AuditPreflightInterface::class);
        $auditPreflight->method('failureReason')->willReturn($preflightFailure);

        return new EnvironmentDoctor(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver($environment)),
            $xdgConfigPathResolver,
            $composerAvailabilityChecker,
            $auditPreflight,
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

    private function installBridge(): void
    {
        (new Filesystem())->dumpFile($this->dataHome.'/symfony-security-auditor/vendor/autoload.php', "<?php\n");
    }
}
