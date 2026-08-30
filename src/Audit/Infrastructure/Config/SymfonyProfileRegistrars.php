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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\ServiceRegistrarInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar\SymfonySkillRegistrar;

/**
 * The framework knowledge a host adds on top of {@see CoreCompositionRoot} to
 * audit a Symfony application. A host auditing another framework passes its own
 * list instead, which is what keeps one project from being prompted with
 * another framework's surfaces.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyProfileRegistrars
{
    /**
     * @return list<ServiceRegistrarInterface>
     */
    public static function all(): array
    {
        return [new SymfonySkillRegistrar()];
    }
}
