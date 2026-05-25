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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle;

use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Test\InMemoryPlatform;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

#[RunTestsInSeparateProcesses]
final class SymfonySecurityAuditorBundleTest extends TestCase
{
    private string $tmpDir;

    private ?Kernel $bootedKernel = null;

    public function test_bundle_boots_with_minimal_config_and_registers_audit_command(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(AuditCommand::class, $this->getPrivateService($kernel, AuditCommand::class));
    }

    public function test_bundle_default_model_is_claude_opus_4_5(): void
    {
        $kernel = $this->boot([]);

        self::assertSame('claude-opus-4-7', $kernel->getContainer()->getParameter('symfony_security_auditor.attacker_model'));
        self::assertSame('claude-opus-4-7', $kernel->getContainer()->getParameter('symfony_security_auditor.reviewer_model'));
    }

    public function test_bundle_uses_shared_model_for_both_agents_when_split_overrides_omitted(): void
    {
        $kernel = $this->boot(['model' => 'claude-opus']);

        self::assertSame('claude-opus', $kernel->getContainer()->getParameter('symfony_security_auditor.attacker_model'));
        self::assertSame('claude-opus', $kernel->getContainer()->getParameter('symfony_security_auditor.reviewer_model'));
    }

    public function test_bundle_honors_split_model_overrides(): void
    {
        $kernel = $this->boot([
            'model' => 'claude-haiku',
            'attacker_model' => 'claude-opus',
            'reviewer_model' => 'claude-sonnet',
        ]);

        self::assertSame('claude-opus', $kernel->getContainer()->getParameter('symfony_security_auditor.attacker_model'));
        self::assertSame('claude-sonnet', $kernel->getContainer()->getParameter('symfony_security_auditor.reviewer_model'));
    }

    public function test_bundle_propagates_scan_config_to_parameters(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'scan' => [
                'included_paths' => ['src', 'app'],
                'respect_gitignore' => false,
                'max_file_size_kb' => 1024,
            ],
        ]);
        $container = $kernel->getContainer();

        self::assertSame(['src', 'app'], $container->getParameter('symfony_security_auditor.scan.included_paths'));
        self::assertFalse($container->getParameter('symfony_security_auditor.scan.respect_gitignore'));
        self::assertSame(1024, $container->getParameter('symfony_security_auditor.scan.max_file_size_kb'));
    }

    public function test_bundle_defaults_scan_included_paths_to_symfony_skeleton(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertSame(
            ['src', 'config', 'templates', 'public/index.php'],
            $kernel->getContainer()->getParameter('symfony_security_auditor.scan.included_paths'),
        );
    }

    public function test_bundle_wires_unlimited_audit_budget_when_both_caps_omitted(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        $auditBudget = $this->getPrivateService($kernel, AuditBudget::class);
        self::assertInstanceOf(AuditBudget::class, $auditBudget);
        self::assertTrue($auditBudget->isUnlimited());
    }

    public function test_bundle_wires_token_only_audit_budget(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['budget' => ['max_tokens' => 50_000]],
        ]);

        $auditBudget = $this->getPrivateService($kernel, AuditBudget::class);
        self::assertInstanceOf(AuditBudget::class, $auditBudget);
        self::assertSame(50_000, $auditBudget->maxTokens());
        self::assertNull($auditBudget->maxCostUsd());
    }

    public function test_bundle_wires_cost_only_audit_budget(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['budget' => ['max_cost_usd' => 2.5]],
        ]);

        $auditBudget = $this->getPrivateService($kernel, AuditBudget::class);
        self::assertInstanceOf(AuditBudget::class, $auditBudget);
        self::assertNull($auditBudget->maxTokens());
        self::assertSame(2.5, $auditBudget->maxCostUsd());
    }

    public function test_bundle_wires_both_caps_audit_budget(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['budget' => ['max_tokens' => 10_000, 'max_cost_usd' => 1.0]],
        ]);

        $auditBudget = $this->getPrivateService($kernel, AuditBudget::class);
        self::assertInstanceOf(AuditBudget::class, $auditBudget);
        self::assertSame(10_000, $auditBudget->maxTokens());
        self::assertSame(1.0, $auditBudget->maxCostUsd());
    }

    public function test_bundle_propagates_audit_retry_config_to_parameters(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => [
                'retry' => [
                    'max_attempts' => 5,
                    'initial_delay_ms' => 250,
                    'backoff_multiplier' => 1.5,
                    'jitter_ratio' => 0.1,
                ],
            ],
        ]);
        $container = $kernel->getContainer();

        self::assertSame(5, $container->getParameter('symfony_security_auditor.audit.retry.max_attempts'));
        self::assertSame(250, $container->getParameter('symfony_security_auditor.audit.retry.initial_delay_ms'));
        self::assertSame(1.5, $container->getParameter('symfony_security_auditor.audit.retry.backoff_multiplier'));
        self::assertSame(0.1, $container->getParameter('symfony_security_auditor.audit.retry.jitter_ratio'));
    }

    public function test_bundle_rejects_audit_retry_max_attempts_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['retry' => ['max_attempts' => 0]]]);
    }

    public function test_bundle_rejects_audit_retry_backoff_multiplier_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['retry' => ['backoff_multiplier' => 0.5]]]);
    }

    public function test_bundle_propagates_audit_config_to_parameters(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => [
                'max_iterations' => 5,
                'min_confidence' => 0.75,
                'reviewer_batch_size' => 3,
                'tools_enabled' => false,
                'max_tool_iterations' => 7,
            ],
        ]);
        $container = $kernel->getContainer();

        self::assertSame(5, $container->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertSame(0.75, $container->getParameter('symfony_security_auditor.audit.min_confidence'));
        self::assertSame(3, $container->getParameter('symfony_security_auditor.audit.reviewer_batch_size'));
        self::assertFalse($container->getParameter('symfony_security_auditor.audit.tools_enabled'));
        self::assertSame(7, $container->getParameter('symfony_security_auditor.audit.max_tool_iterations'));
    }

    public function test_bundle_propagates_cache_config_to_parameters(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'cache' => [
                'enabled' => false,
                'dir' => '/custom/cache/path',
                'prompt_caching' => false,
            ],
        ]);
        $container = $kernel->getContainer();

        self::assertFalse($container->getParameter('symfony_security_auditor.cache.enabled'));
        self::assertSame('/custom/cache/path', $container->getParameter('symfony_security_auditor.cache.dir'));
        self::assertFalse($container->getParameter('symfony_security_auditor.cache.prompt_caching'));
    }

    public function test_bundle_wires_filesystem_attacker_cache_when_cache_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        self::assertInstanceOf(FilesystemAttackerCache::class, $this->getPrivateService($kernel, AttackerCacheInterface::class));
    }

    public function test_bundle_wires_null_attacker_cache_when_cache_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => false]]);

        self::assertInstanceOf(NullAttackerCache::class, $this->getPrivateService($kernel, AttackerCacheInterface::class));
    }

    public function test_bundle_propagates_secret_scrubbing_config_to_parameters(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'scan' => [
                'secret_scrubbing' => [
                    'enabled' => false,
                    'additional_patterns' => ['/CUSTOM-[A-Z]{6}/'],
                ],
            ],
        ]);
        $container = $kernel->getContainer();

        self::assertFalse($container->getParameter('symfony_security_auditor.scan.secret_scrubbing.enabled'));
        self::assertSame(['/CUSTOM-[A-Z]{6}/'], $container->getParameter('symfony_security_auditor.scan.secret_scrubbing.additional_patterns'));
    }

    public function test_bundle_wires_regex_secret_scrubber_by_default(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(RegexSecretScrubber::class, $this->getPrivateService($kernel, SecretScrubberInterface::class));
    }

    public function test_bundle_wires_null_secret_scrubber_when_scrubbing_disabled(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'scan' => ['secret_scrubbing' => ['enabled' => false]],
        ]);

        self::assertInstanceOf(NullSecretScrubber::class, $this->getPrivateService($kernel, SecretScrubberInterface::class));
    }

    public function test_bundle_wires_composer_audit_advisory_database_as_default_implementation(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(ComposerAuditAdvisoryDatabase::class, $this->getPrivateService($kernel, AdvisoryDatabaseInterface::class));
    }

    public function test_bundle_wires_llm_client_alias_to_attacker_client(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(LLMClientInterface::class, $this->getPrivateService($kernel, LLMClientInterface::class));
    }

    public function test_bundle_wires_null_rate_limiter_when_no_rate_limit_dimension_configured(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(NullRateLimiter::class, $this->getPrivateService($kernel, RateLimiterInterface::class));
    }

    public function test_bundle_wires_token_bucket_rate_limiter_when_any_dimension_configured(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => [
                'rate_limit' => [
                    'requests_per_minute' => 50,
                ],
            ],
        ]);

        self::assertInstanceOf(TokenBucketRateLimiter::class, $this->getPrivateService($kernel, RateLimiterInterface::class));
    }

    public function test_bundle_wires_attacker_agent(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(AttackerAgent::class, $this->getPrivateService($kernel, AttackerAgentInterface::class));
    }

    public function test_bundle_wires_reviewer_agent(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(ReviewerAgent::class, $this->getPrivateService($kernel, ReviewerAgentInterface::class));
    }

    public function test_bundle_wires_run_audit_use_case(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(RunAuditUseCase::class, $this->getPrivateService($kernel, RunAuditUseCase::class));
    }

    private function getPrivateService(Kernel $kernel, string $id): object
    {
        $testContainer = $kernel->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);

        return $testContainer->get($id);
    }

    public function test_bundle_rejects_max_file_size_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'scan' => ['max_file_size_kb' => 0]]);
    }

    public function test_bundle_accepts_max_file_size_at_one(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'scan' => ['max_file_size_kb' => 1]]);

        self::assertSame(1, $kernel->getContainer()->getParameter('symfony_security_auditor.scan.max_file_size_kb'));
    }

    public function test_bundle_rejects_min_confidence_above_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['min_confidence' => 1.5]]);
    }

    public function test_bundle_rejects_max_iterations_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['max_iterations' => 0]]);
    }

    public function test_bundle_accepts_max_iterations_at_one(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['max_iterations' => 1]]);

        self::assertSame(1, $kernel->getContainer()->getParameter('symfony_security_auditor.audit.max_iterations'));
    }

    public function test_bundle_rejects_reviewer_batch_size_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['reviewer_batch_size' => 0]]);
    }

    public function test_bundle_accepts_reviewer_batch_size_at_one(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['reviewer_batch_size' => 1]]);

        self::assertSame(1, $kernel->getContainer()->getParameter('symfony_security_auditor.audit.reviewer_batch_size'));
    }

    public function test_bundle_rejects_max_tool_iterations_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['max_tool_iterations' => 0]]);
    }

    public function test_bundle_accepts_max_tool_iterations_at_one(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['max_tool_iterations' => 1]]);

        self::assertSame(1, $kernel->getContainer()->getParameter('symfony_security_auditor.audit.max_tool_iterations'));
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/bundle_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        if ($this->bootedKernel instanceof Kernel) {
            $this->bootedKernel->shutdown();
            $this->bootedKernel = null;
        }

        if (is_dir($this->tmpDir)) {
            (new Filesystem())->remove($this->tmpDir);
        }
    }

    /**
     * @param array<string, mixed> $bundleConfig
     */
    private function boot(array $bundleConfig): Kernel
    {
        $tmpDir = $this->tmpDir;
        $kernel = new class('test', true, $tmpDir, $bundleConfig) extends Kernel {
            /** @var array<string, mixed> */
            private array $bundleConfig;

            private string $tmpDir;

            /**
             * @param array<string, mixed> $bundleConfig
             */
            public function __construct(string $environment, bool $debug, string $tmpDir, array $bundleConfig)
            {
                parent::__construct($environment, $debug);
                $this->tmpDir = $tmpDir;
                $this->bundleConfig = $bundleConfig;
            }

            public function registerBundles(): iterable
            {
                yield new FrameworkBundle();
                yield new SymfonySecurityAuditorBundle();
            }

            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $bundleConfig = $this->bundleConfig;
                $loader->load(static function (ContainerBuilder $containerBuilder) use ($bundleConfig): void {
                    $containerBuilder->loadFromExtension('framework', [
                        'secret' => 'test',
                        'http_method_override' => false,
                        'handle_all_throwables' => true,
                        'test' => true,
                        'validation' => ['email_validation_mode' => 'html5'],
                        'php_errors' => ['log' => true],
                    ]);
                    $containerBuilder->loadFromExtension('symfony_security_auditor', $bundleConfig);

                    $containerBuilder->register(PlatformInterface::class, InMemoryPlatform::class)
                        ->setArguments(['stub-response'])
                        ->setPublic(true);
                });
            }

            public function getProjectDir(): string
            {
                return $this->tmpDir;
            }

            public function getCacheDir(): string
            {
                return $this->tmpDir.'/cache';
            }

            public function getLogDir(): string
            {
                return $this->tmpDir.'/log';
            }
        };

        $kernel->boot();

        $this->bootedKernel = $kernel;

        return $kernel;
    }
}
