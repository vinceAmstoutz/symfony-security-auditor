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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\FrameworkProfileInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony\SymfonyChunkingRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony\SymfonyClassifierRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony\SymfonyPromptRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony\SymfonySkillRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony\SymfonySourceParserRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony\SymfonyStaticPreScanRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony\SymfonyToolRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

/**
 * The framework knowledge a host adds on top of {@see CoreCompositionRoot} to
 * audit a Symfony application. A host auditing another framework passes its own
 * profile instead, which is what keeps one project from being prompted with
 * another framework's surfaces.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyProfile implements FrameworkProfileInterface
{
    /**
     * @return list<ServiceRegistrarInterface>
     */
    #[Override]
    public function registrars(): array
    {
        return [
            new SymfonyClassifierRegistrar(),
            new SymfonyChunkingRegistrar(),
            new SymfonySourceParserRegistrar(),
            new SymfonyStaticPreScanRegistrar(),
            new SymfonySkillRegistrar(),
            new SymfonyPromptRegistrar(),
            new SymfonyToolRegistrar(),
        ];
    }

    #[Override]
    public function promptVersions(): PromptVersions
    {
        return new PromptVersions(
            attacker: AttackerPromptBuilder::PROMPT_VERSION,
            reviewer: ReviewerPromptBuilder::PROMPT_VERSION,
        );
    }
}
