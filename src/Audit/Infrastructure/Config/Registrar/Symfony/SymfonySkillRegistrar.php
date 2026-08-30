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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SymfonySkillSet;

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

    #[Override]
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        foreach (SymfonySkillSet::classNames() as $skill) {
            $servicesConfigurator->set($skill)->tag(self::SKILL_TAG);
        }
    }
}
