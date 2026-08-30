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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\CustomAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Skill\ConfiguredAttackerSkill;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;

/**
 * Each configured `audit.custom_skills` entry becomes a tagged
 * `ConfiguredAttackerSkill`, so `AttackerSkillRegistry`'s tagged iterator
 * collects it beside the built-in skills with no registry change.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CustomSkillRegistrar implements ServiceRegistrarInterface
{
    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        foreach ($bundleConfiguration->audit->customSkills as $index => $customSkill) {
            $servicesConfigurator->set(\sprintf('security_auditor.custom_skill.%d', $index), ConfiguredAttackerSkill::class)
                ->private()
                ->args([
                    inline_service(CustomAttackerSkill::class)->args([
                        $customSkill->name,
                        $customSkill->fileType,
                        $customSkill->instructions,
                        $customSkill->priority,
                    ]),
                ])
                ->tag('symfony_security_auditor.attacker_skill');
        }
    }
}
