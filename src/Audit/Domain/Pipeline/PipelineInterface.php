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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;

interface PipelineInterface
{
    public function process(AuditContext $auditContext): void;
}
