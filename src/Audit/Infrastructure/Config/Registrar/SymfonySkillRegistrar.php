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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar;

use Override;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ApiResourceAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AuthenticatorAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerEasyAdminAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerFileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerTrustBoundaryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EntityAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EntityFileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EventSubscriberAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FormAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\LdapServiceAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\LiveComponentAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\MessengerHandlerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\NormalizerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SchedulerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SonataAdminAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TemplateAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TrustBoundaryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TwigExtensionAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\VoterAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\WebhookConsumerAttackerSkill;

/**
 * The Symfony profile's attacker skills. These are framework knowledge, not core
 * wiring: a host auditing a different framework registers its own set instead,
 * so no project is ever prompted with another framework's surfaces.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonySkillRegistrar implements ServiceRegistrarInterface
{
    private const string SKILL_TAG = 'symfony_security_auditor.attacker_skill';

    /**
     * @return list<class-string>
     */
    private function skills(): array
    {
        return [
            ApiResourceAttackerSkill::class,
            AuthenticatorAttackerSkill::class,
            ConfigAttackerSkill::class,
            ControllerAttackerSkill::class,
            ControllerEasyAdminAttackerSkill::class,
            ControllerFileUploadAttackerSkill::class,
            ControllerTrustBoundaryAttackerSkill::class,
            EntityAttackerSkill::class,
            EntityFileUploadAttackerSkill::class,
            EventSubscriberAttackerSkill::class,
            FileUploadAttackerSkill::class,
            FormAttackerSkill::class,
            LdapServiceAttackerSkill::class,
            LiveComponentAttackerSkill::class,
            MessengerHandlerAttackerSkill::class,
            NormalizerAttackerSkill::class,
            PhpAttackerSkill::class,
            RepositoryAttackerSkill::class,
            SchedulerAttackerSkill::class,
            SonataAdminAttackerSkill::class,
            TemplateAttackerSkill::class,
            TrustBoundaryAttackerSkill::class,
            TwigExtensionAttackerSkill::class,
            VoterAttackerSkill::class,
            WebhookConsumerAttackerSkill::class,
        ];
    }

    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        foreach ($this->skills() as $skill) {
            $servicesConfigurator->set($skill)->tag(self::SKILL_TAG);
        }
    }
}
