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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class JsonReportRenderer implements ReportRendererInterface
{
    #[Override]
    public function format(): string
    {
        return 'json';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        return json_encode($auditReport->toArray(), \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR | \JSON_INVALID_UTF8_SUBSTITUTE | \JSON_PRESERVE_ZERO_FRACTION);
    }
}
