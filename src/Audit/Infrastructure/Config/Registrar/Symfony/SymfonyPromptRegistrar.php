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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\Symfony;

use Override;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AttackerSkillPromptRendererInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Feedback\ReviewerFeedbackHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSections;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSectionsInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/**
 * The prompts themselves. Every word of these is Symfony vocabulary — voters,
 * Twig, Doctrine — so a host auditing another framework registers its own.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyPromptRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(AttackerSkillRegistry::class)
            ->args([tagged_iterator('symfony_security_auditor.attacker_skill')]);
        $servicesConfigurator->alias(AttackerSkillPromptRendererInterface::class, AttackerSkillRegistry::class);

        $servicesConfigurator->set(AttackerPromptBuilder::class)
            ->args([
                param('symfony_security_auditor.audit.structured_collection'),
                param('symfony_security_auditor.audit.stable_system_prompt'),
                service(AttackerSkillRegistry::class),
            ]);
        $servicesConfigurator->alias(AttackerPromptBuilderInterface::class, AttackerPromptBuilder::class);

        $servicesConfigurator->set(ReviewerPromptSections::class);
        $servicesConfigurator->alias(ReviewerPromptSectionsInterface::class, ReviewerPromptSections::class);
        $servicesConfigurator->set(ReviewerMessageRenderer::class);
        $servicesConfigurator->alias(ReviewerMessageRendererInterface::class, ReviewerMessageRenderer::class);
        $servicesConfigurator->set(ReviewerFeedbackHolder::class);

        $servicesConfigurator->set(ReviewerPromptBuilder::class)
            ->args([
                param('symfony_security_auditor.audit.reviewer_structured_collection'),
                service(ReviewerPromptSectionsInterface::class),
                service(ReviewerMessageRendererInterface::class),
                service(ReviewerFeedbackProviderInterface::class),
            ]);
        $servicesConfigurator->alias(ReviewerPromptBuilderInterface::class, ReviewerPromptBuilder::class);
    }
}
