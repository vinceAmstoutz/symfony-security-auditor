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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Skill\AttackerSkillInterface;

/**
 * The attack surfaces this profile knows about in a Symfony application. It is
 * the only place the built-in set is enumerated: the container tags these
 * classes from here, and the non-container fallback instantiates the same list.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonySkillSet
{
    /**
     * @return list<class-string<AttackerSkillInterface>>
     */
    public static function classNames(): array
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

    /**
     * @return list<AttackerSkillInterface>
     */
    public static function all(): array
    {
        return array_map(
            static fn (string $skill): AttackerSkillInterface => new $skill(),
            self::classNames(),
        );
    }
}
