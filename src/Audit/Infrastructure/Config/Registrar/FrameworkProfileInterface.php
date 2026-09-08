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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PromptVersions;

/**
 * The framework knowledge a host adds on top of the core audit graph: the
 * attacker skills, source parsers and prompts that only make sense for the
 * framework being audited, plus the versions of the prompts they produce.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface FrameworkProfileInterface
{
    /**
     * @return list<ServiceRegistrarInterface>
     */
    public function registrars(): array;

    public function promptVersions(): PromptVersions;
}
