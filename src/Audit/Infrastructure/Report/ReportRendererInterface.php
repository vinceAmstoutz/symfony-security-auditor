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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/** @internal one implementation per output format — see docs/versioning.md */
interface ReportRendererInterface
{
    /**
     * Wire-format identifier matching the `OutputFormat` enum value
     * (`console`, `json`, `sarif`, `html`, `markdown`, `junit`, `github`); the
     * Command layer selects the renderer by this key.
     */
    public function format(): string;

    public function render(AuditReport $auditReport): string;
}
