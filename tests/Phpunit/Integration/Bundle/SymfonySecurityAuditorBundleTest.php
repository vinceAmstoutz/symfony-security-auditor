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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Test\InMemoryPlatform;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
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

    public function test_bundle_boots_without_an_ai_platform_service(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o'], registerPlatform: false);

        self::assertInstanceOf(AuditCommand::class, $this->getPrivateService($kernel, AuditCommand::class));
    }

    public function test_bundle_default_model_is_claude_opus_4_8(): void
    {
        $kernel = $this->boot([]);

        self::assertSame('claude-opus-4-8', $kernel->getContainer()->getParameter('symfony_security_auditor.attacker_model'));
        self::assertSame('claude-opus-4-8', $kernel->getContainer()->getParameter('symfony_security_auditor.reviewer_model'));
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

    public function test_bundle_defaults_max_output_tokens_to_4096_for_both_agents(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);
        $container = $kernel->getContainer();

        self::assertSame(4096, $container->getParameter('symfony_security_auditor.attacker_max_output_tokens'));
        self::assertSame(4096, $container->getParameter('symfony_security_auditor.reviewer_max_output_tokens'));
    }

    public function test_bundle_honors_split_max_output_tokens_overrides(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'attacker_max_output_tokens' => 8192,
            'reviewer_max_output_tokens' => 2048,
        ]);
        $container = $kernel->getContainer();

        self::assertSame(8192, $container->getParameter('symfony_security_auditor.attacker_max_output_tokens'));
        self::assertSame(2048, $container->getParameter('symfony_security_auditor.reviewer_max_output_tokens'));
    }

    public function test_bundle_max_output_tokens_falls_back_to_shared_cap_when_overrides_omitted(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'max_output_tokens' => 6000,
        ]);
        $container = $kernel->getContainer();

        self::assertSame(6000, $container->getParameter('symfony_security_auditor.attacker_max_output_tokens'));
        self::assertSame(6000, $container->getParameter('symfony_security_auditor.reviewer_max_output_tokens'));
    }

    public function test_bundle_rejects_max_output_tokens_below_one(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => 'gpt-4o', 'max_output_tokens' => 0]);
    }

    public function test_bundle_defaults_structured_collection_to_true_so_provider_validates_findings(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertTrue($kernel->getContainer()->getParameter('symfony_security_auditor.audit.structured_collection'));
    }

    public function test_bundle_propagates_structured_collection_opt_out_to_parameter(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['structured_collection' => false],
        ]);

        self::assertFalse($kernel->getContainer()->getParameter('symfony_security_auditor.audit.structured_collection'));
    }

    public function test_bundle_defaults_reviewer_structured_collection_to_true(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertTrue($kernel->getContainer()->getParameter('symfony_security_auditor.audit.reviewer_structured_collection'));
    }

    public function test_bundle_propagates_reviewer_structured_collection_opt_out_to_parameter(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_structured_collection' => false],
        ]);

        self::assertFalse($kernel->getContainer()->getParameter('symfony_security_auditor.audit.reviewer_structured_collection'));
    }

    public function test_bundle_defaults_stable_system_prompt_to_true(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertTrue($kernel->getContainer()->getParameter('symfony_security_auditor.audit.stable_system_prompt'));
    }

    public function test_bundle_propagates_stable_system_prompt_opt_in_to_parameter(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['stable_system_prompt' => true],
        ]);

        self::assertTrue($kernel->getContainer()->getParameter('symfony_security_auditor.audit.stable_system_prompt'));
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
            ],
        ]);
        $container = $kernel->getContainer();

        self::assertFalse($container->getParameter('symfony_security_auditor.cache.enabled'));
        self::assertSame('/custom/cache/path', $container->getParameter('symfony_security_auditor.cache.dir'));
    }

    public function test_bundle_accepts_deprecated_prompt_caching_key_and_still_exposes_its_value(): void
    {
        $this->expectUserDeprecationMessageMatches('/The "prompt_caching" option is deprecated and no longer has any effect/');

        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'cache' => [
                'prompt_caching' => false,
            ],
        ]);

        self::assertFalse($kernel->getContainer()->getParameter('symfony_security_auditor.cache.prompt_caching'));
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

    public function test_bundle_wires_filesystem_reviewer_cache_when_cache_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        self::assertInstanceOf(FilesystemReviewerCache::class, $this->getPrivateService($kernel, ReviewerCacheInterface::class));
    }

    public function test_bundle_wires_null_reviewer_cache_when_cache_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => false]]);

        self::assertInstanceOf(NullReviewerCache::class, $this->getPrivateService($kernel, ReviewerCacheInterface::class));
    }

    public function test_bundle_reviewer_cache_dir_and_salt_derive_from_cache_dir_and_reviewer_model(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'reviewer_model' => 'claude-haiku-4-5-20251001',
            'cache' => ['dir' => '/custom/cache'],
        ]);
        $container = $kernel->getContainer();

        self::assertSame('/custom/cache/reviewer', $container->getParameter('symfony_security_auditor.cache.reviewer_dir'));
        self::assertSame(
            \sprintf('claude-haiku-4-5-20251001|reviewer-v%d|prompt-v%d', FilesystemReviewerCache::CACHE_VERSION, ReviewerPromptBuilder::PROMPT_VERSION),
            $container->getParameter('symfony_security_auditor.cache.reviewer_key_salt'),
        );
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

    public function test_bundle_wires_regex_static_pre_scanner_by_default(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(RegexStaticPreScanner::class, $this->getPrivateService($kernel, StaticPreScannerInterface::class));
    }

    public function test_bundle_wires_null_static_pre_scanner_when_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['static_prescan' => ['enabled' => false]]]);

        self::assertInstanceOf(NullStaticPreScanner::class, $this->getPrivateService($kernel, StaticPreScannerInterface::class));
    }

    public function test_bundle_wires_regex_code_slicer_when_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['enabled' => true]]]);

        self::assertInstanceOf(RegexCodeSlicer::class, $this->getPrivateService($kernel, CodeSlicerInterface::class));
    }

    public function test_bundle_wires_null_code_slicer_by_default(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(NullCodeSlicer::class, $this->getPrivateService($kernel, CodeSlicerInterface::class));
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

    public function test_bundle_exposes_audit_defaults_as_parameters(): void
    {
        $container = $this->boot(['model' => 'gpt-4o'])->getContainer();

        self::assertSame(1, $container->getParameter('symfony_security_auditor.audit.reviewer_max_concurrent'));
        self::assertSame(80, $container->getParameter('symfony_security_auditor.audit.code_slicing.min_lines_before_slicing'));
        self::assertTrue($container->getParameter('symfony_security_auditor.audit.static_prescan.enabled'));
        self::assertFalse($container->getParameter('symfony_security_auditor.audit.code_slicing.enabled'));
        self::assertNull($container->getParameter('symfony_security_auditor.audit.budget.max_tokens'));
        self::assertNull($container->getParameter('symfony_security_auditor.audit.budget.max_cost_usd'));
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('integerNodeMinimumCases')]
    public function test_bundle_accepts_integer_node_at_its_documented_minimum(array $config, string $parameter, int $expected): void
    {
        $container = $this->boot($config)->getContainer();

        self::assertSame($expected, $container->getParameter($parameter));
    }

    /** @return iterable<string, array{array<string, mixed>, string, int}> */
    public static function integerNodeMinimumCases(): iterable
    {
        yield 'reviewer_max_concurrent' => [['model' => 'gpt-4o', 'audit' => ['reviewer_max_concurrent' => 1]], 'symfony_security_auditor.audit.reviewer_max_concurrent', 1];
        yield 'attacker_max_concurrent' => [['model' => 'gpt-4o', 'audit' => ['attacker_max_concurrent' => 1]], 'symfony_security_auditor.audit.attacker_max_concurrent', 1];
        yield 'reviewer_max_tool_iterations' => [['model' => 'gpt-4o', 'audit' => ['reviewer_max_tool_iterations' => 1]], 'symfony_security_auditor.audit.reviewer_max_tool_iterations', 1];
        yield 'code_slicing min_lines' => [['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['min_lines_before_slicing' => 10]]], 'symfony_security_auditor.audit.code_slicing.min_lines_before_slicing', 10];
        yield 'budget max_tokens' => [['model' => 'gpt-4o', 'audit' => ['budget' => ['max_tokens' => 1]]], 'symfony_security_auditor.audit.budget.max_tokens', 1];
        yield 'retry max_attempts' => [['model' => 'gpt-4o', 'audit' => ['retry' => ['max_attempts' => 1]]], 'symfony_security_auditor.audit.retry.max_attempts', 1];
        yield 'retry initial_delay_ms' => [['model' => 'gpt-4o', 'audit' => ['retry' => ['initial_delay_ms' => 0]]], 'symfony_security_auditor.audit.retry.initial_delay_ms', 0];
        yield 'attacker_max_output_tokens' => [['model' => 'gpt-4o', 'attacker_max_output_tokens' => 1], 'symfony_security_auditor.attacker_max_output_tokens', 1];
        yield 'reviewer_max_output_tokens' => [['model' => 'gpt-4o', 'reviewer_max_output_tokens' => 1], 'symfony_security_auditor.reviewer_max_output_tokens', 1];
        yield 'max_output_tokens' => [['model' => 'gpt-4o', 'max_output_tokens' => 1], 'symfony_security_auditor.attacker_max_output_tokens', 1];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('integerNodeBelowMinimumCases')]
    public function test_bundle_rejects_integer_node_below_its_documented_minimum(array $config): void
    {
        $this->expectException(Throwable::class);

        $this->boot($config);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function integerNodeBelowMinimumCases(): iterable
    {
        yield 'reviewer_max_concurrent' => [['model' => 'gpt-4o', 'audit' => ['reviewer_max_concurrent' => 0]]];
        yield 'attacker_max_concurrent' => [['model' => 'gpt-4o', 'audit' => ['attacker_max_concurrent' => 0]]];
        yield 'reviewer_max_tool_iterations' => [['model' => 'gpt-4o', 'audit' => ['reviewer_max_tool_iterations' => 0]]];
        yield 'code_slicing min_lines' => [['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['min_lines_before_slicing' => 9]]]];
        yield 'budget max_tokens' => [['model' => 'gpt-4o', 'audit' => ['budget' => ['max_tokens' => 0]]]];
        yield 'retry initial_delay_ms' => [['model' => 'gpt-4o', 'audit' => ['retry' => ['initial_delay_ms' => -1]]]];
        yield 'attacker_max_output_tokens' => [['model' => 'gpt-4o', 'attacker_max_output_tokens' => 0]];
        yield 'reviewer_max_output_tokens' => [['model' => 'gpt-4o', 'reviewer_max_output_tokens' => 0]];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('rateLimitDimensionBelowMinimumCases')]
    public function test_bundle_rejects_rate_limit_dimension_below_one(array $config): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->boot($config);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function rateLimitDimensionBelowMinimumCases(): iterable
    {
        yield 'requests_per_minute' => [['model' => 'gpt-4o', 'audit' => ['rate_limit' => ['requests_per_minute' => 0]]]];
        yield 'input_tokens_per_minute' => [['model' => 'gpt-4o', 'audit' => ['rate_limit' => ['input_tokens_per_minute' => 0]]]];
        yield 'output_tokens_per_minute' => [['model' => 'gpt-4o', 'audit' => ['rate_limit' => ['output_tokens_per_minute' => 0]]]];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('rateLimitDimensionMinimumCases')]
    public function test_bundle_accepts_each_rate_limit_dimension_at_its_minimum(array $config): void
    {
        $kernel = $this->boot($config);

        self::assertInstanceOf(TokenBucketRateLimiter::class, $this->getPrivateService($kernel, RateLimiterInterface::class));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function rateLimitDimensionMinimumCases(): iterable
    {
        yield 'requests_per_minute' => [['model' => 'gpt-4o', 'audit' => ['rate_limit' => ['requests_per_minute' => 1]]]];
        yield 'input_tokens_per_minute' => [['model' => 'gpt-4o', 'audit' => ['rate_limit' => ['input_tokens_per_minute' => 1]]]];
        yield 'output_tokens_per_minute' => [['model' => 'gpt-4o', 'audit' => ['rate_limit' => ['output_tokens_per_minute' => 1]]]];
    }

    #[DataProvider('chunkingStrategyCases')]
    public function test_bundle_accepts_each_chunking_strategy(string $strategy): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['chunking' => ['strategy' => $strategy]]]);

        self::assertSame($strategy, $kernel->getContainer()->getParameter('symfony_security_auditor.audit.chunking.strategy'));
    }

    /** @return iterable<string, array{string}> */
    public static function chunkingStrategyCases(): iterable
    {
        yield 'feature' => ['feature'];
        yield 'type' => ['type'];
    }

    #[DataProvider('pocSeverityFloorCases')]
    public function test_bundle_accepts_each_poc_synthesis_severity_floor(string $severityFloor): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['poc_synthesis' => ['severity_floor' => $severityFloor]]]);

        self::assertSame($severityFloor, $kernel->getContainer()->getParameter('symfony_security_auditor.audit.poc_synthesis.severity_floor'));
    }

    /** @return iterable<string, array{string}> */
    public static function pocSeverityFloorCases(): iterable
    {
        yield 'critical' => ['critical'];
        yield 'high' => ['high'];
        yield 'medium' => ['medium'];
        yield 'low' => ['low'];
        yield 'info' => ['info'];
    }

    public function test_bundle_derives_advisory_cache_dir_from_cache_dir(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['dir' => '/custom/cache']]);

        self::assertSame('/custom/cache/advisory', $kernel->getContainer()->getParameter('symfony_security_auditor.cache.advisory_dir'));
    }

    public function test_bundle_cache_key_salt_embeds_a_sixteen_char_truncated_pattern_hash(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        $expectedPatternHash = substr(hash('sha256', json_encode([], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES)), 0, 16);
        $expectedKeySalt = \sprintf(
            'gpt-4o|prompt-v%d|prescan-v%d|patterns-%s|collect-tool|skills-full',
            AttackerPromptBuilder::PROMPT_VERSION,
            RegexStaticPreScanner::CACHE_VERSION,
            $expectedPatternHash,
        );

        self::assertSame($expectedKeySalt, $kernel->getContainer()->getParameter('symfony_security_auditor.cache.key_salt'));
    }

    public function test_bundle_cache_key_salt_folds_in_the_structured_collection_mode(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['structured_collection' => false]]);

        $keySalt = $kernel->getContainer()->getParameter('symfony_security_auditor.cache.key_salt');
        self::assertIsString($keySalt);
        self::assertStringContainsString('|collect-json|', $keySalt);
    }

    public function test_bundle_cache_key_salt_folds_in_the_stable_system_prompt_flag(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['stable_system_prompt' => false]]);

        $keySalt = $kernel->getContainer()->getParameter('symfony_security_auditor.cache.key_salt');
        self::assertIsString($keySalt);
        self::assertStringEndsWith('|skills-lean', $keySalt);
    }

    public function test_bundle_fast_profile_resolves_cost_levers(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'profile' => 'fast']);
        $container = $kernel->getContainer();

        self::assertSame(1, $container->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertTrue($container->getParameter('symfony_security_auditor.audit.static_prescan.lean_mode'));
        self::assertTrue($container->getParameter('symfony_security_auditor.audit.code_slicing.enabled'));
        self::assertFalse($container->getParameter('symfony_security_auditor.audit.poc_synthesis.enabled'));
        self::assertSame(4, $container->getParameter('symfony_security_auditor.audit.reviewer_max_concurrent'));
        self::assertSame(4, $container->getParameter('symfony_security_auditor.audit.attacker_max_concurrent'));
    }

    public function test_bundle_thorough_profile_enables_poc_synthesis(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'profile' => 'thorough']);
        $container = $kernel->getContainer();

        self::assertTrue($container->getParameter('symfony_security_auditor.audit.poc_synthesis.enabled'));
        self::assertSame(3, $container->getParameter('symfony_security_auditor.audit.max_iterations'));
    }

    public function test_bundle_explicit_key_overrides_the_profile(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'profile' => 'fast',
            'audit' => ['max_iterations' => 2],
        ]);

        self::assertSame(2, $kernel->getContainer()->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertTrue($kernel->getContainer()->getParameter('symfony_security_auditor.audit.static_prescan.lean_mode'));
    }

    public function test_bundle_default_profile_keeps_balanced_defaults(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);
        $container = $kernel->getContainer();

        self::assertSame(3, $container->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertFalse($container->getParameter('symfony_security_auditor.audit.static_prescan.lean_mode'));
        self::assertFalse($container->getParameter('symfony_security_auditor.audit.code_slicing.enabled'));
        self::assertFalse($container->getParameter('symfony_security_auditor.audit.poc_synthesis.enabled'));
        self::assertSame(1, $container->getParameter('symfony_security_auditor.audit.reviewer_max_concurrent'));
        self::assertSame(1, $container->getParameter('symfony_security_auditor.audit.attacker_max_concurrent'));
    }

    public function test_bundle_config_notices_default_to_an_empty_list(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertSame([], $kernel->getContainer()->getParameter('symfony_security_auditor.config_notices'));
    }

    public function test_bundle_baseline_parameter_defaults_to_null(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertNull($kernel->getContainer()->getParameter('symfony_security_auditor.audit.baseline'));
    }

    public function test_bundle_baseline_parameter_reflects_the_configured_path(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['baseline' => '.security-baseline.json']]);

        self::assertSame('.security-baseline.json', $kernel->getContainer()->getParameter('symfony_security_auditor.audit.baseline'));
    }

    public function test_bundle_emits_a_notice_when_batching_disables_the_reviewer_verdict_cache(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['reviewer_batch_size' => 5]]);

        $configNotices = $kernel->getContainer()->getParameter('symfony_security_auditor.config_notices');
        self::assertIsArray($configNotices);
        self::assertCount(1, $configNotices);
        self::assertIsString($configNotices[0]);
        self::assertStringContainsString('reviewer-verdict cache', $configNotices[0]);
        self::assertStringContainsString('audit.reviewer_batch_size', $configNotices[0]);
    }

    public function test_bundle_emits_no_batching_notice_when_the_cache_is_disabled(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_batch_size' => 5],
            'cache' => ['enabled' => false],
        ]);

        self::assertSame([], $kernel->getContainer()->getParameter('symfony_security_auditor.config_notices'));
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
    private function boot(array $bundleConfig, bool $registerPlatform = true): Kernel
    {
        $tmpDir = $this->tmpDir;
        $kernel = new class('test', true, $tmpDir, $bundleConfig, $registerPlatform) extends Kernel {
            /** @var array<string, mixed> */
            private array $bundleConfig;

            private string $tmpDir;

            private bool $registerPlatform;

            /**
             * @param array<string, mixed> $bundleConfig
             */
            public function __construct(string $environment, bool $debug, string $tmpDir, array $bundleConfig, bool $registerPlatform)
            {
                parent::__construct($environment, $debug);
                $this->tmpDir = $tmpDir;
                $this->bundleConfig = $bundleConfig;
                $this->registerPlatform = $registerPlatform;
            }

            public function registerBundles(): iterable
            {
                yield new FrameworkBundle();
                yield new SymfonySecurityAuditorBundle();
            }

            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $bundleConfig = $this->bundleConfig;
                $registerPlatform = $this->registerPlatform;
                $loader->load(static function (ContainerBuilder $containerBuilder) use ($bundleConfig, $registerPlatform): void {
                    $containerBuilder->loadFromExtension('framework', [
                        'secret' => 'test',
                        'http_method_override' => false,
                        'handle_all_throwables' => true,
                        'test' => true,
                        'validation' => ['email_validation_mode' => 'html5'],
                        'php_errors' => ['log' => true],
                    ]);
                    $containerBuilder->loadFromExtension('symfony_security_auditor', $bundleConfig);

                    if ($registerPlatform) {
                        $containerBuilder->register(PlatformInterface::class, InMemoryPlatform::class)
                            ->setArguments(['stub-response'])
                            ->setPublic(true);
                    }
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
