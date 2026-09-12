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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableAuditCommandException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;

final class StandaloneAuditEndToEndTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    private string $cacheHome;

    private string $projectDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-e2e-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-e2e-cache-'.$suffix;
        $this->projectDir = sys_get_temp_dir().'/ssa-e2e-project-'.$suffix;

        $this->filesystem->dumpFile(
            $this->configHome.'/symfony-security-auditor/config.yaml',
            "platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\nmodel: 'gpt-4'\n",
        );

        $this->filesystem->dumpFile(
            $this->projectDir.'/src/Controller/HomeController.php',
            '<?php class HomeController { public function index(): void {} }',
        );
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->configHome, $this->cacheHome, $this->projectDir]);
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_standalone_application_audits_a_project_end_to_end_in_dry_run(): void
    {
        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        $commandTester = new CommandTester($standaloneApplication->find(AuditCommand::NAME));

        $exitCode = $commandTester->execute(['project-path' => $this->projectDir, '--dry-run' => true]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Dry run complete.', $commandTester->getDisplay());
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_a_dry_run_estimates_cost_without_a_provider_credential(): void
    {
        self::assertSame(
            0,
            $this->runWithCredentialFromEnvironment(\sprintf('%s %s --dry-run', AuditCommand::NAME, $this->projectDir)),
        );
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_a_real_run_still_refuses_to_start_without_a_provider_credential(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('PROVIDER_API_KEY');

        $this->runWithCredentialFromEnvironment(\sprintf('%s %s', AuditCommand::NAME, $this->projectDir));
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_a_real_run_refuses_to_start_when_the_credential_file_cannot_be_read(): void
    {
        $missingCredentialFile = \sprintf('%s/absent-api-key', $this->configHome);

        $this->expectException(UnreadableCredentialFileException::class);
        $this->expectExceptionMessage($missingCredentialFile);

        $this->runWithCredentialFromFile(\sprintf('%s %s', AuditCommand::NAME, $this->projectDir), $missingCredentialFile);
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    private function runWithCredentialFromEnvironment(string $commandLine): int
    {
        return $this->runWithPlatformCredential($commandLine, '%env(PROVIDER_API_KEY)%');
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    private function runWithCredentialFromFile(string $commandLine, string $credentialFile): int
    {
        return $this->runWithPlatformCredential(
            $commandLine,
            '%env(file:PROVIDER_API_KEY_FILE)%',
            ['PROVIDER_API_KEY_FILE' => $credentialFile],
        );
    }

    /**
     * @param array<string, string> $extraEnvironment
     *
     * @throws UnresolvableConfigPathException
     */
    private function runWithPlatformCredential(string $commandLine, string $apiKeyExpression, array $extraEnvironment = []): int
    {
        $this->filesystem->dumpFile(
            $this->configHome.'/symfony-security-auditor/config.yaml',
            \sprintf("platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\n      api_key: '%s'\nmodel: 'gpt-4'\n", $apiKeyExpression),
        );

        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
            ...$extraEnvironment,
        ])->create();
        $standaloneApplication->setAutoExit(false);
        $standaloneApplication->setCatchExceptions(false);

        return $standaloneApplication->run(new StringInput($commandLine), new BufferedOutput());
    }
}
