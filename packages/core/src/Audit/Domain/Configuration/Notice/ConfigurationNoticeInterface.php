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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\Notice;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\AuditExecutionConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\LLMConfiguration;

/**
 * One rule per configuration footgun. Returning a list rather than a single
 * message lets a rule report once per affected role.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ConfigurationNoticeInterface
{
    /**
     * @return list<string>
     */
    public function noticesFor(AuditExecutionConfiguration $auditExecutionConfiguration, LLMConfiguration $llmConfiguration): array;
}
