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

use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableAuditCommandException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneConsoleCommandFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

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
    public function test_the_standalone_application_audits_a_project_end_to_end_in_dry_run(): void
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create();

        $commandTester = new CommandTester($application->find(AuditCommand::NAME));

        $exitCode = $commandTester->execute(['project-path' => $this->projectDir, '--dry-run' => true]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Dry run complete.', $commandTester->getDisplay());
    }

    /**
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    #[RunInSeparateProcess]
    public function test_the_standalone_composition_root_runs_a_full_audit_and_reports_the_finding(): void
    {
        $commandTester = $this->classicRunCommandTester($this->criticalFindingResponse());

        $exitCode = $commandTester->execute(['project-path' => $this->projectDir]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('sql_injection', $commandTester->getDisplay());
    }

    /**
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    #[RunInSeparateProcess]
    public function test_the_standalone_composition_root_reports_a_safe_project(): void
    {
        $commandTester = $this->classicRunCommandTester('[]');

        $exitCode = $commandTester->execute(['project-path' => $this->projectDir]);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringContainsString('SAFE', $commandTester->getDisplay());
    }

    /**
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    #[RunInSeparateProcess]
    public function test_the_standalone_composition_root_emits_valid_json(): void
    {
        $commandTester = $this->classicRunCommandTester($this->criticalFindingResponse());

        $commandTester->execute(['project-path' => $this->projectDir, '--format' => 'json']);

        preg_match('/(\{.*\})/s', $commandTester->getDisplay(), $matches);
        $decoded = json_decode($matches[1] ?? '', true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('risk_level', $decoded);
    }

    /**
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws AmbiguousPlatformException
     * @throws UnresolvableAuditCommandException
     */
    private function classicRunCommandTester(string $attackerResponse): CommandTester
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('model')->willReturn('gpt-4');
        $llmClient->method('complete')->willReturnCallback(
            static fn (string $systemPrompt): LLMResponse => LLMResponse::of(
                str_contains($systemPrompt, 'security code reviewer') ? '{"accepted": true}' : $attackerResponse,
                'stub',
                'end_turn',
                TokenUsageSnapshot::of(0, 0),
            ),
        );

        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['model' => 'gpt-4', 'audit' => ['structured_collection' => false, 'reviewer_structured_collection' => false, 'tools_enabled' => false]],
                new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]]),
            ),
            $this->cacheHome,
            $llmClient,
        );

        return new CommandTester((new StandaloneConsoleCommandFactory())->create($containerBuilder));
    }

    private function criticalFindingResponse(): string
    {
        $findings = [];
        for ($index = 1; $index <= 5; ++$index) {
            $findings[] = [
                'type' => 'sql_injection',
                'severity' => 'critical',
                'title' => \sprintf('SQL injection #%d', $index),
                'description' => 'Raw query built from user input',
                'file_path' => \sprintf('src/Repository/Repo%d.php', $index),
                'line_start' => 1,
                'line_end' => 1,
                'vulnerable_code' => 'public function index()',
                'attack_vector' => 'Query parameter',
                'proof' => "' OR 1=1--",
                'remediation' => 'Use prepared statements',
                'confidence' => 0.95,
            ];
        }

        return (string) json_encode($findings);
    }
}
