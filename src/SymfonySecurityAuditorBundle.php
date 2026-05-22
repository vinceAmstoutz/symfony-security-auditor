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

namespace VinceAmstoutz\SymfonySecurityAuditor;

use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class SymfonySecurityAuditorBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('model')
                    ->defaultValue('gpt-4o')
                    ->info('Model name for both Attacker and Reviewer. Must be supported by the configured platform.')
                ->end()
                ->scalarNode('attacker_model')
                    ->defaultNull()
                    ->info('Override: dedicated model for the Attacker role. Falls back to `model` when null.')
                ->end()
                ->scalarNode('reviewer_model')
                    ->defaultNull()
                    ->info('Override: dedicated model for the Reviewer role. Falls back to `model` when null.')
                ->end()
                ->arrayNode('scan')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->arrayNode('excluded_dirs')
                            ->info('Additional directories to exclude. Appended to hard defaults (vendor, node_modules, .git, var/cache, var/log, public/bundles); never replaces them.')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->booleanNode('respect_gitignore')
                            ->defaultTrue()
                            ->info('When true, files ignored by the project .gitignore are excluded from the scan. Default true — matches the host project intent (committed code only) and avoids analyzing generated/cached artefacts. Set false for full-tree scans (rare).')
                        ->end()
                        ->integerNode('max_file_size_kb')
                            ->defaultValue(ProjectFileScanner::DEFAULT_MAX_FILE_SIZE_KB)
                            ->min(1)
                            ->info('Skip files larger than this size, in kilobytes.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('audit')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('max_iterations')
                            ->defaultValue(AuditOrchestrator::DEFAULT_MAX_ITERATIONS)
                            ->min(1)
                            ->info('Maximum number of attacker/reviewer iterations per audit.')
                        ->end()
                        ->floatNode('min_confidence')
                            ->defaultValue(AuditOrchestrator::DEFAULT_MIN_CONFIDENCE)
                            ->min(0.0)
                            ->max(1.0)
                            ->info('Minimum attacker self-reported confidence (0.0–1.0) required to forward a finding to the reviewer.')
                        ->end()
                        ->integerNode('reviewer_batch_size')
                            ->defaultValue(ReviewerAgent::DEFAULT_BATCH_SIZE)
                            ->min(1)
                            ->info('Number of findings reviewed per LLM call. 1 = one finding per call (highest precision, highest latency). Higher values reduce cost and latency at the risk of cross-talk between findings in the prompt.')
                        ->end()
                        ->booleanNode('tools_enabled')
                            ->defaultTrue()
                            ->info('Give the attacker access to tools (read_file, grep, list_files, lookup_advisory) for cross-file investigation. Default true — without tools, lookup_advisory is dead weight and the attacker is blind across files. Costs more LLM round-trips per chunk; combine with cache.prompt_caching on Anthropic.')
                        ->end()
                        ->integerNode('max_tool_iterations')
                            ->defaultValue(AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS)
                            ->min(1)
                            ->info('Maximum tool-call rounds per chunk before forcing the attacker to commit to a final answer. Bounds runaway tool use.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('cache')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultTrue()
                            ->info('Enable content-hash cache for attacker chunks. Skips the LLM call when an identical chunk has been analyzed before. Default true — huge cost saver on repeated runs (CI, PR scans).')
                        ->end()
                        ->scalarNode('dir')
                            ->defaultValue('%kernel.cache_dir%/symfony_security_auditor/attacker')
                            ->info('Filesystem path for the attacker cache. Created on first write.')
                        ->end()
                        ->booleanNode('prompt_caching')
                            ->defaultTrue()
                            ->info('Opt into provider-side prompt caching by setting `cache_control: ephemeral` on every LLM call. Default true — honored by Anthropic for ~90% input-token discount; silently ignored by other providers (zero cost to leave on).')
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;
    }

    /**
     * @param array{
     *     model: string,
     *     attacker_model: string|null,
     *     reviewer_model: string|null,
     *     scan: array{excluded_dirs: list<string>, respect_gitignore: bool, max_file_size_kb: int},
     *     audit: array{max_iterations: int, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, max_tool_iterations: int},
     *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
     * } $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        $attackerModel = $config['attacker_model'] ?? $config['model'];
        $reviewerModel = $config['reviewer_model'] ?? $config['model'];

        $builder->setParameter('symfony_security_auditor.attacker_model', (string) $attackerModel);
        $builder->setParameter('symfony_security_auditor.reviewer_model', (string) $reviewerModel);
        $builder->setParameter('symfony_security_auditor.scan.excluded_dirs', $config['scan']['excluded_dirs']);
        $builder->setParameter('symfony_security_auditor.scan.respect_gitignore', $config['scan']['respect_gitignore']);
        $builder->setParameter('symfony_security_auditor.scan.max_file_size_kb', $config['scan']['max_file_size_kb']);
        $builder->setParameter('symfony_security_auditor.audit.max_iterations', $config['audit']['max_iterations']);
        $builder->setParameter('symfony_security_auditor.audit.min_confidence', $config['audit']['min_confidence']);
        $builder->setParameter('symfony_security_auditor.audit.reviewer_batch_size', $config['audit']['reviewer_batch_size']);
        $builder->setParameter('symfony_security_auditor.audit.tools_enabled', $config['audit']['tools_enabled']);
        $builder->setParameter('symfony_security_auditor.audit.max_tool_iterations', $config['audit']['max_tool_iterations']);
        $builder->setParameter('symfony_security_auditor.cache.enabled', $config['cache']['enabled']);
        $builder->setParameter('symfony_security_auditor.cache.dir', $config['cache']['dir']);
        $builder->setParameter('symfony_security_auditor.cache.prompt_caching', $config['cache']['prompt_caching']);

        $services = $container->services();

        $services->set('security_auditor.attacker_client', SymfonyAiLLMClient::class)
            ->private()
            ->args([
                service(PlatformInterface::class),
                $attackerModel,
                service('logger'),
                SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                $config['cache']['prompt_caching'],
            ]);

        $services->set('security_auditor.reviewer_client', SymfonyAiLLMClient::class)
            ->private()
            ->args([
                service(PlatformInterface::class),
                $reviewerModel,
                service('logger'),
                SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                $config['cache']['prompt_caching'],
            ]);

        $services->alias(LLMClientInterface::class, 'security_auditor.attacker_client');

        $cacheServiceId = $config['cache']['enabled']
            ? FilesystemAttackerCache::class
            : NullAttackerCache::class;
        $services->alias(AttackerCacheInterface::class, $cacheServiceId);

        $services->alias(AdvisoryDatabaseInterface::class, ComposerAuditAdvisoryDatabase::class);
    }
}
