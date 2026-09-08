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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * The single source of `AttackerAgent`'s constructor argument shape, shared by
 * the primary and escalation (cheap-model) service definitions so they cannot
 * drift out of sync with each other or with the constructor itself.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerAgentDefinitionFactory
{
    /**
     * @return list<mixed>
     */
    public function args(string $llmClientServiceId, string $attackerCacheServiceId = AttackerCacheInterface::class): array
    {
        return [
            inline_service(AttackerLlmCollaborators::class)->args([
                service($llmClientServiceId),
                service(AttackerPromptBuilderInterface::class),
                service(VulnerabilityFactory::class),
                service(CodeSlicerInterface::class),
                service(RecordVulnerabilityToolFactoryInterface::class),
            ]),
            inline_service(AttackerScanCollaborators::class)->args([
                service($attackerCacheServiceId),
                service(StaticPreScannerInterface::class),
                service(ProgressReporterInterface::class),
                service(FileChunker::class),
                service(ToolRegistryFactoryInterface::class),
            ]),
            inline_service(AttackerAnalysisSettings::class)->args([
                param('symfony_security_auditor.audit.tools_enabled'),
                param('symfony_security_auditor.audit.max_tool_iterations'),
                param('symfony_security_auditor.audit.static_prescan.lean_mode'),
                param('symfony_security_auditor.audit.structured_collection'),
                param('symfony_security_auditor.audit.attacker_max_concurrent'),
            ]),
            service('logger'),
        ];
    }
}
