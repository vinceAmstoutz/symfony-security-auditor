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

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Test\InMemoryPlatform;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\DependencyExpansionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\CustomAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullTriageMemoryRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\DeferredAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemTriageMemoryStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\CompositeReviewerFeedbackProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfiguredAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SarifImportingPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

final class SymfonySecurityAuditorBundleTest extends TestCase
{
    private string $tmpDir;

    private ?Kernel $bootedKernel = null;

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_boots_with_minimal_config_and_registers_audit_command(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(AuditCommand::class, $this->getPrivateService($kernel, AuditCommand::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_dependency_expansion_stage_between_mapping_and_audit(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        $auditPipeline = $this->getPrivateService($kernel, AuditPipeline::class);
        self::assertInstanceOf(AuditPipeline::class, $auditPipeline);

        $stageClasses = array_map(static fn (object $stage): string => $stage::class, $auditPipeline->stages());
        $mappingIndex = array_search(MappingStage::class, $stageClasses, true);
        $dependencyExpansionIndex = array_search(DependencyExpansionStage::class, $stageClasses, true);
        $auditIndex = array_search(AuditStage::class, $stageClasses, true);

        self::assertNotFalse($mappingIndex);
        self::assertNotFalse($dependencyExpansionIndex);
        self::assertNotFalse($auditIndex);
        self::assertGreaterThan($mappingIndex, $dependencyExpansionIndex);
        self::assertLessThan($auditIndex, $dependencyExpansionIndex);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_registers_every_built_in_attacker_skill(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        $attackerSkillRegistry = $this->getPrivateService($kernel, AttackerSkillRegistry::class);
        self::assertInstanceOf(AttackerSkillRegistry::class, $attackerSkillRegistry);

        self::assertSame(new AttackerSkillRegistry()->render([], true), $attackerSkillRegistry->render([], true));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_boots_without_an_ai_platform_service(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o'], registerPlatform: false);

        self::assertInstanceOf(AuditCommand::class, $this->getPrivateService($kernel, AuditCommand::class));
    }

    public function test_bundle_default_model_is_claude_opus_4_8(): void
    {
        $containerBuilder = $this->loadParameters([]);

        self::assertSame('claude-opus-4-8', $containerBuilder->getParameter('symfony_security_auditor.attacker_model'));
        self::assertSame('claude-opus-4-8', $containerBuilder->getParameter('symfony_security_auditor.reviewer_model'));
    }

    public function test_bundle_uses_shared_model_for_both_agents_when_split_overrides_omitted(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'claude-opus']);

        self::assertSame('claude-opus', $containerBuilder->getParameter('symfony_security_auditor.attacker_model'));
        self::assertSame('claude-opus', $containerBuilder->getParameter('symfony_security_auditor.reviewer_model'));
    }

    public function test_bundle_honors_split_model_overrides(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'claude-haiku',
            'attacker_model' => 'claude-opus',
            'reviewer_model' => 'claude-sonnet',
        ]);

        self::assertSame('claude-opus', $containerBuilder->getParameter('symfony_security_auditor.attacker_model'));
        self::assertSame('claude-sonnet', $containerBuilder->getParameter('symfony_security_auditor.reviewer_model'));
    }

    public function test_bundle_defaults_max_output_tokens_to_4096_for_both_agents(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame(4096, $containerBuilder->getParameter('symfony_security_auditor.attacker_max_output_tokens'));
        self::assertSame(4096, $containerBuilder->getParameter('symfony_security_auditor.reviewer_max_output_tokens'));
    }

    public function test_bundle_honors_split_max_output_tokens_overrides(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'attacker_max_output_tokens' => 8192,
            'reviewer_max_output_tokens' => 2048,
        ]);

        self::assertSame(8192, $containerBuilder->getParameter('symfony_security_auditor.attacker_max_output_tokens'));
        self::assertSame(2048, $containerBuilder->getParameter('symfony_security_auditor.reviewer_max_output_tokens'));
    }

    public function test_bundle_max_output_tokens_falls_back_to_shared_cap_when_overrides_omitted(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'max_output_tokens' => 6000,
        ]);

        self::assertSame(6000, $containerBuilder->getParameter('symfony_security_auditor.attacker_max_output_tokens'));
        self::assertSame(6000, $containerBuilder->getParameter('symfony_security_auditor.reviewer_max_output_tokens'));
    }

    public function test_the_budget_guard_checks_pricing_for_the_escalation_cheap_model_too(): void
    {
        $containerBuilder = $this->loadParameters([
            'attacker_model' => 'gpt-4o',
            'reviewer_model' => 'gpt-4o-mini',
            'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-3.5-turbo']],
        ]);

        self::assertSame(
            ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'],
            $containerBuilder->getParameter('symfony_security_auditor.audit.models_requiring_pricing'),
        );
    }

    public function test_the_budget_guard_checks_only_the_distinct_configured_models_without_escalation(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame(
            ['gpt-4o'],
            $containerBuilder->getParameter('symfony_security_auditor.audit.models_requiring_pricing'),
        );
    }

    public function test_bundle_defers_composer_audit_until_the_run_sets_the_audited_project_path(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame(DeferredAdvisoryDatabase::class, (string) $containerBuilder->getAlias(AdvisoryDatabaseInterface::class));
        $definition = $containerBuilder->getDefinition(DeferredAdvisoryDatabase::class);
        $pathArgument = $definition->getArgument(1);
        self::assertInstanceOf(Reference::class, $pathArgument);
        self::assertSame(AuditedProjectPathHolder::class, (string) $pathArgument);
    }

    public function test_bundle_does_not_register_escalation_services_by_default(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertFalse($containerBuilder->hasDefinition(EscalatingAttackerAgent::class));
        self::assertFalse($containerBuilder->hasDefinition('security_auditor.cheap_attacker'));
        self::assertFalse($containerBuilder->hasDefinition('security_auditor.cheap_attacker_client'));
    }

    public function test_bundle_registers_escalation_services_and_aliases_the_attacker_agent_when_enabled(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => [
                'escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini'],
                'tools_enabled' => false,
                'max_tool_iterations' => 7,
                'static_prescan' => ['lean_mode' => true],
                'structured_collection' => false,
                'attacker_max_concurrent' => 3,
            ],
        ]);

        self::assertTrue($containerBuilder->hasDefinition('security_auditor.cheap_attacker_client'));
        self::assertTrue($containerBuilder->hasDefinition('security_auditor.cheap_attacker'));
        self::assertTrue($containerBuilder->hasDefinition(EscalatingAttackerAgent::class));
        self::assertTrue($containerBuilder->hasAlias(AttackerAgentInterface::class));
        self::assertSame(EscalatingAttackerAgent::class, (string) $containerBuilder->getAlias(AttackerAgentInterface::class));
        $cheapAttackerDefinition = $containerBuilder->getDefinition('security_auditor.cheap_attacker');

        $cheapAttackerLlmCollaborators = $cheapAttackerDefinition->getArgument(0);
        self::assertInstanceOf(Definition::class, $cheapAttackerLlmCollaborators);
        self::assertSame(AttackerLlmCollaborators::class, $cheapAttackerLlmCollaborators->getClass());
        $cheapAttackerClientArgument = $cheapAttackerLlmCollaborators->getArgument(0);
        self::assertInstanceOf(Reference::class, $cheapAttackerClientArgument);
        self::assertSame('security_auditor.cheap_attacker_client', (string) $cheapAttackerClientArgument);

        $cheapAttackerAnalysisSettings = $cheapAttackerDefinition->getArgument(2);
        self::assertInstanceOf(Definition::class, $cheapAttackerAnalysisSettings);
        self::assertSame(AttackerAnalysisSettings::class, $cheapAttackerAnalysisSettings->getClass());
        self::assertSame(
            [false, 7, true, false, 3],
            $containerBuilder->getParameterBag()->resolveValue($cheapAttackerAnalysisSettings->getArguments()),
        );

        $escalatingAttackerFirstArgument = $containerBuilder->getDefinition(EscalatingAttackerAgent::class)->getArgument(0);
        self::assertInstanceOf(Reference::class, $escalatingAttackerFirstArgument);
        self::assertSame('security_auditor.cheap_attacker', (string) $escalatingAttackerFirstArgument);
    }

    public function test_bundle_wires_escalation_attacker_agent_from_the_same_argument_shape_as_the_primary_one(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini']],
        ]);

        $primaryArguments = $containerBuilder->getDefinition(AttackerAgent::class)->getArguments();
        $escalationArguments = $containerBuilder->getDefinition('security_auditor.cheap_attacker')->getArguments();

        self::assertCount(4, $primaryArguments);
        self::assertCount(4, $escalationArguments);

        self::assertInstanceOf(Definition::class, $primaryArguments[0]);
        self::assertInstanceOf(Definition::class, $escalationArguments[0]);
        self::assertSame($primaryArguments[0]->getClass(), $escalationArguments[0]->getClass());
        self::assertEquals(
            \array_slice($primaryArguments[0]->getArguments(), 1),
            \array_slice($escalationArguments[0]->getArguments(), 1),
        );

        self::assertInstanceOf(Definition::class, $primaryArguments[1]);
        self::assertInstanceOf(Definition::class, $escalationArguments[1]);
        self::assertSame($primaryArguments[1]->getClass(), $escalationArguments[1]->getClass());
        self::assertEquals(
            \array_slice($primaryArguments[1]->getArguments(), 1),
            \array_slice($escalationArguments[1]->getArguments(), 1),
        );
        self::assertEquals($primaryArguments[2], $escalationArguments[2]);
        self::assertEquals($primaryArguments[3], $escalationArguments[3]);
    }

    public function test_bundle_gives_the_cheap_attacker_its_own_cache_so_cheap_results_never_reach_the_primary_attacker(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini']],
        ]);

        $cheapCacheDefinition = $containerBuilder->getDefinition('security_auditor.cheap_attacker_cache');
        self::assertSame(FilesystemAttackerCache::class, $cheapCacheDefinition->getClass());
        self::assertSame(
            '%symfony_security_auditor.cache.cheap_attacker_key_salt%',
            $cheapCacheDefinition->getArgument(3),
        );

        $cheapScanCollaborators = $containerBuilder->getDefinition('security_auditor.cheap_attacker')->getArgument(1);
        self::assertInstanceOf(Definition::class, $cheapScanCollaborators);
        $cheapCacheReference = $cheapScanCollaborators->getArgument(0);
        self::assertInstanceOf(Reference::class, $cheapCacheReference);
        self::assertSame('security_auditor.cheap_attacker_cache', (string) $cheapCacheReference);
    }

    public function test_bundle_aliases_the_cheap_attacker_cache_to_the_null_cache_when_caching_is_disabled(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini']],
            'cache' => ['enabled' => false],
        ]);

        self::assertTrue($containerBuilder->hasAlias('security_auditor.cheap_attacker_cache'));
        self::assertSame(NullAttackerCache::class, (string) $containerBuilder->getAlias('security_auditor.cheap_attacker_cache'));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_escalating_attacker_agent_when_escalation_enabled(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini']],
        ]);

        self::assertInstanceOf(EscalatingAttackerAgent::class, $this->getPrivateService($kernel, AttackerAgentInterface::class));
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_max_output_tokens_below_one(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => 'gpt-4o', 'max_output_tokens' => 0]);
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_an_empty_model(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => '']);
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_an_empty_attacker_model(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => 'gpt-4o', 'attacker_model' => '']);
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_an_empty_reviewer_model(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => 'gpt-4o', 'reviewer_model' => '']);
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_an_empty_escalation_cheap_model(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => 'gpt-4o', 'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => '']]]);
    }

    public function test_bundle_accepts_a_null_attacker_model_falling_back_to_model(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'attacker_model' => null]);

        self::assertSame('gpt-4o', $containerBuilder->getParameter('symfony_security_auditor.attacker_model'));
    }

    public function test_bundle_defaults_structured_collection_to_true_so_provider_validates_findings(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.structured_collection'));
    }

    public function test_bundle_propagates_structured_collection_opt_out_to_parameter(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['structured_collection' => false],
        ]);

        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.structured_collection'));
    }

    public function test_bundle_defaults_reviewer_structured_collection_to_true(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_structured_collection'));
    }

    public function test_bundle_propagates_reviewer_structured_collection_opt_out_to_parameter(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_structured_collection' => false],
        ]);

        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_structured_collection'));
    }

    public function test_bundle_defaults_stable_system_prompt_to_true(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.stable_system_prompt'));
    }

    public function test_bundle_propagates_stable_system_prompt_opt_in_to_parameter(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['stable_system_prompt' => true],
        ]);

        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.stable_system_prompt'));
    }

    public function test_bundle_propagates_scan_config_to_parameters(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'scan' => [
                'included_paths' => ['src', 'app'],
                'respect_gitignore' => false,
                'max_file_size_kb' => 1024,
            ],
        ]);

        self::assertSame(['src', 'app'], $containerBuilder->getParameter('symfony_security_auditor.scan.included_paths'));
        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.scan.respect_gitignore'));
        self::assertSame(1024, $containerBuilder->getParameter('symfony_security_auditor.scan.max_file_size_kb'));
    }

    public function test_bundle_defaults_scan_included_paths_to_symfony_skeleton(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame(
            ['src', 'config', 'templates', 'public/index.php', '.env', '.env.local', '.env.dev', '.env.test', '.env.prod', '.env.dist'],
            $containerBuilder->getParameter('symfony_security_auditor.scan.included_paths'),
        );
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_configured_scan_included_paths_scope_the_show_scanned_listing_end_to_end(): void
    {
        mkdir($this->tmpDir.'/src/Controller/Admin', 0o777, true);
        mkdir($this->tmpDir.'/src/Service', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Controller/HomeController.php', '<?php class HomeController {}');
        file_put_contents($this->tmpDir.'/src/Controller/Admin/DashboardController.php', '<?php class DashboardController {}');
        file_put_contents($this->tmpDir.'/src/Service/PaymentService.php', '<?php class PaymentService {}');

        $kernel = $this->boot(['model' => 'gpt-4o', 'scan' => ['included_paths' => ['src/Controller']]]);
        $auditCommand = $this->getPrivateService($kernel, AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);

        $commandTester = new CommandTester($auditCommand);
        $exitCode = $commandTester->execute([
            'project-path' => $this->tmpDir,
            '--show-scanned' => true,
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $display = $commandTester->getDisplay();
        self::assertStringContainsString('src/Controller/HomeController.php', $display);
        self::assertStringContainsString('src/Controller/Admin/DashboardController.php', $display);
        self::assertStringNotContainsString('PaymentService.php', $display);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_unlimited_audit_budget_when_both_caps_omitted(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        $auditBudget = $this->getPrivateService($kernel, AuditBudget::class);
        self::assertInstanceOf(AuditBudget::class, $auditBudget);
        self::assertTrue($auditBudget->isUnlimited());
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
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

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
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

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
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
        $containerBuilder = $this->loadParameters([
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

        self::assertSame(5, $containerBuilder->getParameter('symfony_security_auditor.audit.retry.max_attempts'));
        self::assertSame(250, $containerBuilder->getParameter('symfony_security_auditor.audit.retry.initial_delay_ms'));
        self::assertSame(1.5, $containerBuilder->getParameter('symfony_security_auditor.audit.retry.backoff_multiplier'));
        self::assertSame(0.1, $containerBuilder->getParameter('symfony_security_auditor.audit.retry.jitter_ratio'));
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_audit_retry_max_attempts_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['retry' => ['max_attempts' => 0]]]);
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_audit_retry_backoff_multiplier_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['retry' => ['backoff_multiplier' => 0.5]]]);
    }

    public function test_bundle_propagates_audit_config_to_parameters(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => [
                'max_iterations' => 5,
                'min_confidence' => 0.75,
                'reviewer_batch_size' => 3,
                'tools_enabled' => false,
                'max_tool_iterations' => 7,
            ],
        ]);

        self::assertSame(5, $containerBuilder->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertSame(0.75, $containerBuilder->getParameter('symfony_security_auditor.audit.min_confidence'));
        self::assertSame(3, $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_batch_size'));
        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.tools_enabled'));
        self::assertSame(7, $containerBuilder->getParameter('symfony_security_auditor.audit.max_tool_iterations'));
    }

    public function test_bundle_propagates_cache_config_to_parameters(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'cache' => [
                'enabled' => false,
                'dir' => '/custom/cache/path',
            ],
        ]);

        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.cache.enabled'));
        self::assertSame('/custom/cache/path', $containerBuilder->getParameter('symfony_security_auditor.cache.dir'));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
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

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_filesystem_attacker_cache_when_cache_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        self::assertInstanceOf(FilesystemAttackerCache::class, $this->getPrivateService($kernel, AttackerCacheInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_null_attacker_cache_when_cache_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => false]]);

        self::assertInstanceOf(NullAttackerCache::class, $this->getPrivateService($kernel, AttackerCacheInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_filesystem_reviewer_cache_when_cache_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        self::assertInstanceOf(FilesystemReviewerCache::class, $this->getPrivateService($kernel, ReviewerCacheInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_null_reviewer_cache_when_cache_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => false]]);

        self::assertInstanceOf(NullReviewerCache::class, $this->getPrivateService($kernel, ReviewerCacheInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_null_triage_memory_recorder_when_triage_memory_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(NullTriageMemoryRecorder::class, $this->getPrivateService($kernel, TriageMemoryRecorderInterface::class));
        self::assertInstanceOf(ReviewerFeedbackHolder::class, $this->getPrivateService($kernel, ReviewerFeedbackProviderInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_filesystem_triage_memory_store_when_triage_memory_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['triage_memory' => true]]);

        self::assertInstanceOf(FilesystemTriageMemoryStore::class, $this->getPrivateService($kernel, TriageMemoryRecorderInterface::class));
        self::assertInstanceOf(CompositeReviewerFeedbackProvider::class, $this->getPrivateService($kernel, ReviewerFeedbackProviderInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_the_ttl_bounded_advisory_cache_when_cache_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        self::assertInstanceOf(LockfileHashedAdvisoryCache::class, $this->getPrivateService($kernel, ComposerAuditRunnerInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_bypasses_the_advisory_cache_when_cache_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => false]]);

        self::assertInstanceOf(SymfonyProcessComposerAuditRunner::class, $this->getPrivateService($kernel, ComposerAuditRunnerInterface::class));
    }

    public function test_bundle_reviewer_cache_dir_and_salt_derive_from_cache_dir_and_reviewer_model(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'reviewer_model' => 'claude-haiku-4-5-20251001',
            'cache' => ['dir' => '/custom/cache'],
        ]);

        self::assertSame('/custom/cache/reviewer', $containerBuilder->getParameter('symfony_security_auditor.cache.reviewer_dir'));
        self::assertSame(
            \sprintf('claude-haiku-4-5-20251001|reviewer-v%d|prompt-v%d|collect-tool|tools-off|batch-1|max-output-4096', FilesystemReviewerCache::CACHE_VERSION, ReviewerPromptBuilder::PROMPT_VERSION),
            $containerBuilder->getParameter('symfony_security_auditor.cache.reviewer_key_salt'),
        );
    }

    public function test_bundle_reviewer_key_salt_folds_in_reviewer_tools_enabled_and_max_iterations(): void
    {
        $toolsOffSalt = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_tools_enabled' => false],
        ])->getParameter('symfony_security_auditor.cache.reviewer_key_salt');

        $toolsOnSalt = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_tools_enabled' => true, 'reviewer_max_tool_iterations' => 7],
        ])->getParameter('symfony_security_auditor.cache.reviewer_key_salt');

        self::assertIsString($toolsOffSalt);
        self::assertIsString($toolsOnSalt);
        self::assertStringContainsString('tools-off', $toolsOffSalt);
        self::assertStringContainsString('tools-on-7', $toolsOnSalt);
        self::assertNotSame($toolsOffSalt, $toolsOnSalt);
    }

    public function test_bundle_reviewer_key_salt_folds_in_reviewer_batch_size(): void
    {
        $batchOneSalt = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_batch_size' => 1],
        ])->getParameter('symfony_security_auditor.cache.reviewer_key_salt');

        $batchFiveSalt = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_batch_size' => 5],
        ])->getParameter('symfony_security_auditor.cache.reviewer_key_salt');

        self::assertNotSame($batchOneSalt, $batchFiveSalt);
    }

    public function test_bundle_reviewer_key_salt_folds_in_the_structured_collection_mode(): void
    {
        $structuredSalt = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_structured_collection' => true],
        ])->getParameter('symfony_security_auditor.cache.reviewer_key_salt');

        $jsonSalt = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['reviewer_structured_collection' => false],
        ])->getParameter('symfony_security_auditor.cache.reviewer_key_salt');

        self::assertNotSame($structuredSalt, $jsonSalt);
        self::assertIsString($structuredSalt);
        self::assertIsString($jsonSalt);
        self::assertStringContainsString('|collect-tool|', $structuredSalt);
        self::assertStringContainsString('|collect-json|', $jsonSalt);
    }

    public function test_bundle_propagates_secret_scrubbing_config_to_parameters(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'scan' => [
                'secret_scrubbing' => [
                    'enabled' => false,
                    'additional_patterns' => ['/CUSTOM-[A-Z]{6}/'],
                ],
            ],
        ]);

        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.scan.secret_scrubbing.enabled'));
        self::assertSame(['/CUSTOM-[A-Z]{6}/'], $containerBuilder->getParameter('symfony_security_auditor.scan.secret_scrubbing.additional_patterns'));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_regex_secret_scrubber_by_default(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(RegexSecretScrubber::class, $this->getPrivateService($kernel, SecretScrubberInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_null_secret_scrubber_when_scrubbing_disabled(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'scan' => ['secret_scrubbing' => ['enabled' => false]],
        ]);

        self::assertInstanceOf(NullSecretScrubber::class, $this->getPrivateService($kernel, SecretScrubberInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_regex_static_pre_scanner_by_default(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(RegexStaticPreScanner::class, $this->getPrivateService($kernel, StaticPreScannerInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_null_static_pre_scanner_when_disabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['static_prescan' => ['enabled' => false]]]);

        self::assertInstanceOf(NullStaticPreScanner::class, $this->getPrivateService($kernel, StaticPreScannerInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_the_sarif_importer_around_the_pre_scanner_when_import_sarif_is_configured(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'scan' => ['import_sarif' => ['psalm.sarif']]]);

        self::assertInstanceOf(SarifImportingPreScanner::class, $this->getPrivateService($kernel, StaticPreScannerInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_the_sarif_importer_even_when_the_regex_pre_scan_is_disabled(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'scan' => ['import_sarif' => ['psalm.sarif']],
            'audit' => ['static_prescan' => ['enabled' => false]],
        ]);

        self::assertInstanceOf(SarifImportingPreScanner::class, $this->getPrivateService($kernel, StaticPreScannerInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_regex_code_slicer_when_enabled(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['enabled' => true]]]);

        self::assertInstanceOf(RegexCodeSlicer::class, $this->getPrivateService($kernel, CodeSlicerInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_null_code_slicer_by_default(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(NullCodeSlicer::class, $this->getPrivateService($kernel, CodeSlicerInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_composer_audit_advisory_database_as_default_implementation(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(DeferredAdvisoryDatabase::class, $this->getPrivateService($kernel, AdvisoryDatabaseInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_llm_client_alias_to_attacker_client(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(LLMClientInterface::class, $this->getPrivateService($kernel, LLMClientInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_null_rate_limiter_when_no_rate_limit_dimension_configured(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(NullRateLimiter::class, $this->getPrivateService($kernel, RateLimiterInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
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

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_attacker_agent(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(AttackerAgent::class, $this->getPrivateService($kernel, AttackerAgentInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_reviewer_agent(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(ReviewerAgent::class, $this->getPrivateService($kernel, ReviewerAgentInterface::class));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_wires_run_audit_use_case(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o']);

        self::assertInstanceOf(RunAuditUseCase::class, $this->getPrivateService($kernel, RunAuditUseCase::class));
    }

    public function test_bundle_exposes_audit_defaults_as_parameters(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_max_concurrent'));
        self::assertSame(80, $containerBuilder->getParameter('symfony_security_auditor.audit.code_slicing.min_lines_before_slicing'));
        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.static_prescan.enabled'));
        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.code_slicing.enabled'));
        self::assertNull($containerBuilder->getParameter('symfony_security_auditor.audit.budget.max_tokens'));
        self::assertNull($containerBuilder->getParameter('symfony_security_auditor.audit.budget.max_cost_usd'));
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('integerNodeMinimumCases')]
    public function test_bundle_accepts_integer_node_at_its_documented_minimum(array $config, string $parameter, int $expected): void
    {
        $containerBuilder = $this->loadParameters($config);

        self::assertSame($expected, $containerBuilder->getParameter($parameter));
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
    #[RunInSeparateProcess]
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
    #[RunInSeparateProcess]
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
    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
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
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['chunking' => ['strategy' => $strategy]]]);

        self::assertSame($strategy, $containerBuilder->getParameter('symfony_security_auditor.audit.chunking.strategy'));
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
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['poc_synthesis' => ['severity_floor' => $severityFloor]]]);

        self::assertSame($severityFloor, $containerBuilder->getParameter('symfony_security_auditor.audit.poc_synthesis.severity_floor'));
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

    #[DataProvider('pocSeverityFloorCases')]
    public function test_bundle_accepts_each_fix_synthesis_severity_floor(string $severityFloor): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['fix_synthesis' => ['severity_floor' => $severityFloor]]]);

        self::assertSame($severityFloor, $containerBuilder->getParameter('symfony_security_auditor.audit.fix_synthesis.severity_floor'));
    }

    public function test_bundle_enables_fix_synthesis_when_configured(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['fix_synthesis' => ['enabled' => true]]]);

        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.fix_synthesis.enabled'));
    }

    public function test_bundle_defaults_since_closure_to_none(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame('none', $containerBuilder->getParameter('symfony_security_auditor.audit.since_closure'));
    }

    public function test_bundle_accepts_a_direct_since_closure(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['since_closure' => 'direct']]);

        self::assertSame('direct', $containerBuilder->getParameter('symfony_security_auditor.audit.since_closure'));
    }

    public function test_bundle_accepts_an_explicit_none_since_closure(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['since_closure' => 'none']]);

        self::assertSame('none', $containerBuilder->getParameter('symfony_security_auditor.audit.since_closure'));
    }

    public function test_bundle_rejects_an_invalid_since_closure(): void
    {
        $this->expectException(Throwable::class);

        $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['since_closure' => 'feature']]);
    }

    public function test_bundle_derives_advisory_cache_dir_from_cache_dir(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'cache' => ['dir' => '/custom/cache']]);

        self::assertSame('/custom/cache/advisory', $containerBuilder->getParameter('symfony_security_auditor.cache.advisory_dir'));
    }

    public function test_bundle_derives_triage_memory_dir_from_cache_dir(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'cache' => ['dir' => '/custom/cache']]);

        self::assertSame('/custom/cache/triage-memory', $containerBuilder->getParameter('symfony_security_auditor.cache.triage_memory_dir'));
    }

    public function test_bundle_defaults_triage_memory_to_disabled(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.triage_memory'));
    }

    public function test_bundle_enables_triage_memory_when_configured(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['triage_memory' => true]]);

        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.triage_memory'));
    }

    public function test_bundle_cache_key_salt_embeds_a_sixteen_char_truncated_pattern_hash(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        $expectedPatternHash = substr(hash('sha256', json_encode([], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES)), 0, 16);
        $expectedKeySalt = \sprintf(
            'gpt-4o|prompt-v%d|prescan-v%d|prescan-on|tools-on-8|patterns-%s|collect-tool|skills-full|slice-off|max-output-4096',
            AttackerPromptBuilder::PROMPT_VERSION,
            RegexStaticPreScanner::CACHE_VERSION,
            $expectedPatternHash,
        );

        self::assertSame($expectedKeySalt, $containerBuilder->getParameter('symfony_security_auditor.cache.key_salt'));
    }

    public function test_bundle_cache_key_salt_has_no_custom_skills_segment_without_custom_skills(): void
    {
        $keySalt = $this->loadParameters(['model' => 'gpt-4o'])->getParameter('symfony_security_auditor.cache.key_salt');

        self::assertIsString($keySalt);
        self::assertStringNotContainsString('|custom-skills-', $keySalt);
    }

    public function test_bundle_cache_key_salt_folds_in_configured_custom_skills(): void
    {
        $keySalt = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['custom_skills' => ['legacy_db' => ['file_type' => 'repository', 'instructions' => 'Use SafeQuery.']]],
        ])->getParameter('symfony_security_auditor.cache.key_salt');

        $expectedSegment = \sprintf(
            '|custom-skills-%s',
            substr(hash('sha256', json_encode(
                [new CustomAttackerSkill('legacy_db', ProjectFileType::REPOSITORY, 'Use SafeQuery.', 500)],
                \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES,
            )), 0, 16),
        );

        self::assertIsString($keySalt);
        self::assertStringEndsWith($expectedSegment, $keySalt);
    }

    public function test_bundle_cache_key_salt_changes_when_a_custom_skill_instruction_changes(): void
    {
        $first = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['custom_skills' => ['legacy_db' => ['file_type' => 'repository', 'instructions' => 'Use SafeQuery.']]],
        ])->getParameter('symfony_security_auditor.cache.key_salt');
        $second = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['custom_skills' => ['legacy_db' => ['file_type' => 'repository', 'instructions' => 'Use SafeQuery everywhere.']]],
        ])->getParameter('symfony_security_auditor.cache.key_salt');

        self::assertNotSame($first, $second);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_registers_a_tagged_attacker_skill_per_custom_skill_entry(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['custom_skills' => ['legacy_db' => ['file_type' => 'repository', 'instructions' => 'All queries go through SafeQuery.']]],
        ]);

        $configuredAttackerSkill = $this->getPrivateService($kernel, 'security_auditor.custom_skill.0');
        self::assertInstanceOf(ConfiguredAttackerSkill::class, $configuredAttackerSkill);
        self::assertStringContainsString('All queries go through SafeQuery.', $configuredAttackerSkill->block());
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(2500)]
    public function test_bundle_defaults_an_omitted_custom_skill_priority_to_500(): void
    {
        $kernel = $this->boot([
            'model' => 'gpt-4o',
            'audit' => ['custom_skills' => ['legacy_db' => ['file_type' => 'repository', 'instructions' => 'x']]],
        ]);

        $configuredAttackerSkill = $this->getPrivateService($kernel, 'security_auditor.custom_skill.0');
        self::assertInstanceOf(ConfiguredAttackerSkill::class, $configuredAttackerSkill);
        self::assertSame(500, $configuredAttackerSkill->priority());
    }

    public function test_bundle_cache_key_salt_folds_in_the_prescan_toggle(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['static_prescan' => ['enabled' => false]]]);

        $keySalt = $containerBuilder->getParameter('symfony_security_auditor.cache.key_salt');
        self::assertIsString($keySalt);
        self::assertStringContainsString('|prescan-off|', $keySalt);
    }

    public function test_bundle_cache_key_salt_folds_in_the_tool_settings(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['tools_enabled' => false]]);

        $keySalt = $containerBuilder->getParameter('symfony_security_auditor.cache.key_salt');
        self::assertIsString($keySalt);
        self::assertStringContainsString('|tools-off|', $keySalt);
    }

    public function test_bundle_cache_key_salt_folds_in_the_tool_iteration_budget(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['tools_enabled' => true, 'max_tool_iterations' => 7]]);

        $keySalt = $containerBuilder->getParameter('symfony_security_auditor.cache.key_salt');
        self::assertIsString($keySalt);
        self::assertStringContainsString('|tools-on-7|', $keySalt);
    }

    public function test_bundle_cheap_attacker_key_salt_embeds_the_cheap_model_instead_of_the_attacker_model(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini']],
        ]);

        $attackerKeySalt = $containerBuilder->getParameter('symfony_security_auditor.cache.key_salt');
        $cheapKeySalt = $containerBuilder->getParameter('symfony_security_auditor.cache.cheap_attacker_key_salt');
        self::assertIsString($attackerKeySalt);
        self::assertIsString($cheapKeySalt);
        self::assertStringStartsWith('gpt-4o|', $attackerKeySalt);
        self::assertStringStartsWith('gpt-4o-mini|', $cheapKeySalt);
        self::assertSame(substr($attackerKeySalt, \strlen('gpt-4o')), substr($cheapKeySalt, \strlen('gpt-4o-mini')));
    }

    public function test_bundle_cache_key_salt_folds_in_the_structured_collection_mode(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['structured_collection' => false]]);

        $keySalt = $containerBuilder->getParameter('symfony_security_auditor.cache.key_salt');
        self::assertIsString($keySalt);
        self::assertStringContainsString('|collect-json|', $keySalt);
    }

    public function test_bundle_cache_key_salt_folds_in_the_stable_system_prompt_flag(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['stable_system_prompt' => false]]);

        $keySalt = $containerBuilder->getParameter('symfony_security_auditor.cache.key_salt');
        self::assertIsString($keySalt);
        self::assertStringContainsString('|skills-lean|', $keySalt);
    }

    public function test_bundle_cache_key_salt_changes_when_code_slicing_is_toggled(): void
    {
        $enabledKeySalt = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['enabled' => true]]])
            ->getParameter('symfony_security_auditor.cache.key_salt');
        $disabledKeySalt = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['enabled' => false]]])
            ->getParameter('symfony_security_auditor.cache.key_salt');

        self::assertNotSame($enabledKeySalt, $disabledKeySalt);
    }

    public function test_bundle_cache_key_salt_changes_when_code_slicing_threshold_changes(): void
    {
        $narrowThresholdKeySalt = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['enabled' => true, 'min_lines_before_slicing' => 10]]])
            ->getParameter('symfony_security_auditor.cache.key_salt');
        $wideThresholdKeySalt = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['code_slicing' => ['enabled' => true, 'min_lines_before_slicing' => 200]]])
            ->getParameter('symfony_security_auditor.cache.key_salt');

        self::assertNotSame($narrowThresholdKeySalt, $wideThresholdKeySalt);
    }

    public function test_bundle_cache_key_salt_changes_when_attacker_max_output_tokens_changes(): void
    {
        $defaultKeySalt = $this->loadParameters(['model' => 'gpt-4o'])
            ->getParameter('symfony_security_auditor.cache.key_salt');
        $raisedKeySalt = $this->loadParameters(['model' => 'gpt-4o', 'attacker_max_output_tokens' => 8192])
            ->getParameter('symfony_security_auditor.cache.key_salt');

        self::assertNotSame($defaultKeySalt, $raisedKeySalt);
    }

    public function test_bundle_reviewer_key_salt_changes_when_reviewer_max_output_tokens_changes(): void
    {
        $defaultKeySalt = $this->loadParameters(['model' => 'gpt-4o'])
            ->getParameter('symfony_security_auditor.cache.reviewer_key_salt');
        $raisedKeySalt = $this->loadParameters(['model' => 'gpt-4o', 'reviewer_max_output_tokens' => 8192])
            ->getParameter('symfony_security_auditor.cache.reviewer_key_salt');

        self::assertNotSame($defaultKeySalt, $raisedKeySalt);
    }

    public function test_bundle_fast_profile_resolves_cost_levers(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'profile' => 'fast']);

        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.static_prescan.lean_mode'));
        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.code_slicing.enabled'));
        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.poc_synthesis.enabled'));
        self::assertSame(4, $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_max_concurrent'));
        self::assertSame(4, $containerBuilder->getParameter('symfony_security_auditor.audit.attacker_max_concurrent'));
        self::assertSame('none', $containerBuilder->getParameter('symfony_security_auditor.audit.since_closure'));
    }

    public function test_bundle_thorough_profile_enables_poc_synthesis(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'profile' => 'thorough']);

        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.poc_synthesis.enabled'));
        self::assertSame(3, $containerBuilder->getParameter('symfony_security_auditor.audit.max_iterations'));
    }

    public function test_bundle_thorough_profile_widens_since_closure_to_direct(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'profile' => 'thorough']);

        self::assertSame('direct', $containerBuilder->getParameter('symfony_security_auditor.audit.since_closure'));
    }

    public function test_bundle_explicit_since_closure_overrides_the_thorough_profile(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'profile' => 'thorough', 'audit' => ['since_closure' => 'none']]);

        self::assertSame('none', $containerBuilder->getParameter('symfony_security_auditor.audit.since_closure'));
    }

    public function test_bundle_explicit_key_overrides_the_profile(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'profile' => 'fast',
            'audit' => ['max_iterations' => 2],
        ]);

        self::assertSame(2, $containerBuilder->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertTrue($containerBuilder->getParameter('symfony_security_auditor.audit.static_prescan.lean_mode'));
    }

    public function test_bundle_default_profile_keeps_balanced_defaults(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame(3, $containerBuilder->getParameter('symfony_security_auditor.audit.max_iterations'));
        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.static_prescan.lean_mode'));
        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.code_slicing.enabled'));
        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.poc_synthesis.enabled'));
        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_max_concurrent'));
        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.audit.attacker_max_concurrent'));
    }

    public function test_bundle_config_notices_default_to_an_empty_list(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame([], $containerBuilder->getParameter('symfony_security_auditor.config_notices'));
    }

    public function test_bundle_lean_mode_is_forced_off_when_the_static_prescanner_is_disabled(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'profile' => 'fast',
            'audit' => ['static_prescan' => ['enabled' => false]],
        ]);

        self::assertFalse($containerBuilder->getParameter('symfony_security_auditor.audit.static_prescan.lean_mode'));
        $notices = $containerBuilder->getParameter('symfony_security_auditor.config_notices');
        self::assertIsArray($notices);
        self::assertContains(
            'audit.static_prescan.lean_mode has no effect while audit.static_prescan.enabled is false: with no risk markers, lean mode would drop every file, so all files are analysed instead. Enable static_prescan to use lean mode, or set lean_mode: false to silence this.',
            $notices,
        );
    }

    public function test_bundle_baseline_parameter_defaults_to_null(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertNull($containerBuilder->getParameter('symfony_security_auditor.audit.baseline'));
    }

    public function test_bundle_baseline_parameter_reflects_the_configured_path(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['baseline' => '.security-baseline.json']]);

        self::assertSame('.security-baseline.json', $containerBuilder->getParameter('symfony_security_auditor.audit.baseline'));
    }

    public function test_bundle_fail_on_parameter_defaults_to_critical(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame('critical', $containerBuilder->getParameter('symfony_security_auditor.audit.fail_on'));
    }

    #[DataProvider('failOnLevelCases')]
    public function test_bundle_accepts_each_fail_on_level(string $level): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['fail_on' => $level]]);

        self::assertSame($level, $containerBuilder->getParameter('symfony_security_auditor.audit.fail_on'));
    }

    /** @return iterable<string, array{string}> */
    public static function failOnLevelCases(): iterable
    {
        yield 'safe' => ['safe'];
        yield 'low' => ['low'];
        yield 'medium' => ['medium'];
        yield 'high' => ['high'];
        yield 'critical' => ['critical'];
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_an_unknown_fail_on_level(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => 'gpt-4o', 'audit' => ['fail_on' => 'severe']]);
    }

    public function test_bundle_excluded_and_included_types_default_to_empty_lists(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o']);

        self::assertSame([], $containerBuilder->getParameter('symfony_security_auditor.audit.excluded_types'));
        self::assertSame([], $containerBuilder->getParameter('symfony_security_auditor.audit.included_types'));
    }

    public function test_bundle_propagates_excluded_and_included_types(): void
    {
        $containerBuilder = $this->loadParameters([
            'model' => 'gpt-4o',
            'audit' => [
                'excluded_types' => ['missing_rate_limiting', 'log_injection'],
                'included_types' => ['sql_injection'],
            ],
        ]);

        self::assertSame(['missing_rate_limiting', 'log_injection'], $containerBuilder->getParameter('symfony_security_auditor.audit.excluded_types'));
        self::assertSame(['sql_injection'], $containerBuilder->getParameter('symfony_security_auditor.audit.included_types'));
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_an_unknown_excluded_type(): void
    {
        $this->expectException(Throwable::class);

        $this->boot(['model' => 'gpt-4o', 'audit' => ['excluded_types' => ['not_a_real_type']]]);
    }

    public function test_bundle_emits_no_notice_for_batched_reviews_now_that_the_cache_covers_them(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['reviewer_batch_size' => 5]]);

        self::assertSame([], $containerBuilder->getParameter('symfony_security_auditor.config_notices'));
    }

    private function getPrivateService(Kernel $kernel, string $id): object
    {
        $testContainer = $kernel->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);

        return $testContainer->get($id);
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_max_file_size_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'scan' => ['max_file_size_kb' => 0]]);
    }

    public function test_bundle_accepts_max_file_size_at_one(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'scan' => ['max_file_size_kb' => 1]]);

        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.scan.max_file_size_kb'));
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_min_confidence_above_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['min_confidence' => 1.5]]);
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_max_cost_usd_below_its_minimum(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['budget' => ['max_cost_usd' => 0.0]]]);
    }

    public function test_bundle_accepts_max_cost_usd_at_its_minimum(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['budget' => ['max_cost_usd' => 0.01]]]);

        self::assertSame(0.01, $containerBuilder->getParameter('symfony_security_auditor.audit.budget.max_cost_usd'));
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_max_iterations_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['max_iterations' => 0]]);
    }

    public function test_bundle_accepts_max_iterations_at_one(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['max_iterations' => 1]]);

        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.audit.max_iterations'));
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_reviewer_batch_size_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['reviewer_batch_size' => 0]]);
    }

    public function test_bundle_accepts_reviewer_batch_size_at_one(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['reviewer_batch_size' => 1]]);

        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_batch_size'));
    }

    #[RunInSeparateProcess]
    public function test_bundle_rejects_max_tool_iterations_below_one(): void
    {
        $this->expectException(Throwable::class);
        $this->boot(['model' => 'gpt-4o', 'audit' => ['max_tool_iterations' => 0]]);
    }

    public function test_bundle_accepts_max_tool_iterations_at_one(): void
    {
        $containerBuilder = $this->loadParameters(['model' => 'gpt-4o', 'audit' => ['max_tool_iterations' => 1]]);

        self::assertSame(1, $containerBuilder->getParameter('symfony_security_auditor.audit.max_tool_iterations'));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/bundle_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
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
     * Loads the bundle extension into a bare container — no kernel boot, no
     * FrameworkBundle compilation — and resolves parameter references. Use this
     * for tests that only assert on container parameters; it is an order of
     * magnitude faster than {@see self::boot()}.
     *
     * @param array<string, mixed> $bundleConfig
     */
    private function loadParameters(array $bundleConfig): ContainerBuilder
    {
        $containerBuilder = new ContainerBuilder(new ParameterBag([
            'kernel.cache_dir' => $this->tmpDir.'/cache',
            'kernel.build_dir' => $this->tmpDir.'/cache',
            'kernel.project_dir' => $this->tmpDir,
            'kernel.environment' => 'test',
            'kernel.debug' => true,
        ]));

        $extension = (new SymfonySecurityAuditorBundle())->getContainerExtension();
        self::assertNotNull($extension);
        $extension->load([$bundleConfig], $containerBuilder);
        $containerBuilder->getParameterBag()->resolve();

        return $containerBuilder;
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

            /**
             * @return iterable<FrameworkBundle|SymfonySecurityAuditorBundle>
             */
            #[Override]
            public function registerBundles(): iterable
            {
                yield new FrameworkBundle();
                yield new SymfonySecurityAuditorBundle();
            }

            #[Override]
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

            #[Override]
            public function getProjectDir(): string
            {
                return $this->tmpDir;
            }

            #[Override]
            public function getCacheDir(): string
            {
                return $this->tmpDir.'/cache';
            }

            #[Override]
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
